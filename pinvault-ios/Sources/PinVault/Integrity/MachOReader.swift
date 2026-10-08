import Foundation

/// The two facts the integrity probes read from the app's own Mach-O: whether
/// the main executable was encrypted by the App Store (`cryptid`), and the
/// entitlements of its code signature. Bounds-checked throughout; anything
/// unexpected reads as "not there" (nil), never as a crash.
enum MachOReader {
    static let mhMagic64: UInt32 = 0xFEED_FACF
    static let fatMagic: UInt32 = 0xCAFE_BABE
    static let fatMagic64: UInt32 = 0xCAFE_BABF
    static let lcEncryptionInfo: UInt32 = 0x21
    static let lcEncryptionInfo64: UInt32 = 0x2C
    static let lcCodeSignature: UInt32 = 0x1D
    static let cpuTypeArm64: UInt32 = 0x0100_000C
    static let superBlobMagic: UInt32 = 0xFADE_0CC0
    static let entitlementsBlobMagic: UInt32 = 0xFADE_7171
    static let entitlementsSlot: UInt32 = 5

    /// `cryptid` of the image at `header` (a loaded 64-bit Mach-O header).
    static func cryptid(header: UnsafeRawPointer) -> UInt32? {
        guard header.loadUnaligned(as: UInt32.self) == mhMagic64 else { return nil }
        let ncmds = header.loadUnaligned(fromByteOffset: 16, as: UInt32.self)
        let sizeofcmds = Int(header.loadUnaligned(fromByteOffset: 20, as: UInt32.self))
        return cryptid(commands: UnsafeRawBufferPointer(start: header + 32, count: sizeofcmds), count: ncmds)
    }

    /// `cryptid` from a buffer of load commands.
    static func cryptid(commands: UnsafeRawBufferPointer, count: UInt32) -> UInt32? {
        var offset = 0
        for _ in 0..<min(count, 4096) {
            guard offset + 8 <= commands.count else { return nil }
            let cmd = commands.loadUnaligned(fromByteOffset: offset, as: UInt32.self)
            let size = Int(commands.loadUnaligned(fromByteOffset: offset + 4, as: UInt32.self))
            guard size >= 8, offset + size <= commands.count else { return nil }
            if (cmd == lcEncryptionInfo64 || cmd == lcEncryptionInfo) && size >= 20 {
                return commands.loadUnaligned(fromByteOffset: offset + 16, as: UInt32.self)
            }
            offset += size
        }
        return nil
    }

    /// The entitlements in the code signature of the executable at `url` (its
    /// arm64 slice when fat); nil when it has no signature or no entitlements.
    static func entitlements(of url: URL) throws -> [String: Any]? {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        return try entitlements(read: { offset, length in
            try handle.seek(toOffset: UInt64(offset))
            return try handle.read(upToCount: length) ?? Data()
        })
    }

    /// The same over a reader of `length` bytes at `offset`; tests feed it bytes.
    static func entitlements(read: (Int, Int) throws -> Data) throws -> [String: Any]? {
        let head = try read(0, 4096)
        guard head.count >= 32 else { return nil }
        var slice = 0
        let magicBE = head.bigEndianUInt32(at: 0)
        if magicBE == fatMagic || magicBE == fatMagic64 {
            let arches = Int(head.bigEndianUInt32(at: 4))
            let entry = magicBE == fatMagic64 ? 32 : 20
            var chosen: Int?
            for index in 0..<min(arches, 32) {
                let at = 8 + index * entry
                guard at + entry <= head.count else { break }
                let offset = magicBE == fatMagic64 ? Int(head.bigEndianUInt64(at: at + 8)) : Int(head.bigEndianUInt32(at: at + 8))
                if chosen == nil || head.bigEndianUInt32(at: at) == cpuTypeArm64 { chosen = offset }
                if head.bigEndianUInt32(at: at) == cpuTypeArm64 { break }
            }
            guard let chosen else { return nil }
            slice = chosen
        }
        let header = slice == 0 ? head : try read(slice, 32)
        guard header.count >= 32, header.littleEndianUInt32(at: 0) == mhMagic64 else { return nil }
        let ncmds = Int(header.littleEndianUInt32(at: 16))
        let sizeofcmds = Int(header.littleEndianUInt32(at: 20))
        guard sizeofcmds > 0, sizeofcmds < 16 * 1024 * 1024 else { return nil }
        let commands = try read(slice + 32, sizeofcmds)
        var offset = 0
        var signature: (offset: Int, size: Int)?
        for _ in 0..<min(ncmds, 4096) {
            guard offset + 8 <= commands.count else { break }
            let cmd = commands.littleEndianUInt32(at: offset)
            let size = Int(commands.littleEndianUInt32(at: offset + 4))
            guard size >= 8, offset + size <= commands.count else { break }
            if cmd == lcCodeSignature && size >= 16 {
                signature = (Int(commands.littleEndianUInt32(at: offset + 8)), Int(commands.littleEndianUInt32(at: offset + 12)))
                break
            }
            offset += size
        }
        guard let signature, signature.size >= 12, signature.size < 64 * 1024 * 1024 else { return nil }
        let blob = try read(slice + signature.offset, signature.size)
        guard blob.count >= 12, blob.bigEndianUInt32(at: 0) == superBlobMagic else { return nil }
        let count = Int(blob.bigEndianUInt32(at: 8))
        for index in 0..<min(count, 64) {
            let at = 12 + index * 8
            guard at + 8 <= blob.count else { break }
            guard blob.bigEndianUInt32(at: at) == entitlementsSlot else { continue }
            let start = Int(blob.bigEndianUInt32(at: at + 4))
            guard start + 8 <= blob.count, blob.bigEndianUInt32(at: start) == entitlementsBlobMagic else { return nil }
            let length = Int(blob.bigEndianUInt32(at: start + 4))
            guard length >= 8, start + length <= blob.count else { return nil }
            let xml = blob.subdata(in: (blob.startIndex + start + 8)..<(blob.startIndex + start + length))
            return try PropertyListSerialization.propertyList(from: xml, format: nil) as? [String: Any]
        }
        return nil
    }
}

private extension Data {
    func bigEndianUInt32(at offset: Int) -> UInt32 {
        guard offset >= 0, offset + 4 <= count else { return 0 }
        return self[(startIndex + offset)..<(startIndex + offset + 4)].reduce(0) { $0 << 8 | UInt32($1) }
    }

    func bigEndianUInt64(at offset: Int) -> UInt64 {
        guard offset >= 0, offset + 8 <= count else { return 0 }
        return self[(startIndex + offset)..<(startIndex + offset + 8)].reduce(0) { $0 << 8 | UInt64($1) }
    }

    func littleEndianUInt32(at offset: Int) -> UInt32 {
        guard offset >= 0, offset + 4 <= count else { return 0 }
        return self[(startIndex + offset)..<(startIndex + offset + 4)].reversed().reduce(0) { $0 << 8 | UInt32($1) }
    }
}
