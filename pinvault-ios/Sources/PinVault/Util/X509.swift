import Foundation
import Security

/// A minimal X.509 v1–v3 certificate parser: the fields the library checks
/// (validity, names, key, SANs, CA flag) and the bytes signatures cover.
struct X509Certificate: Sendable, Equatable {

    /// A distinguished name.
    struct Name: Sendable, Equatable {
        struct Attribute: Sendable, Equatable {
            /// Attribute type, dotted (`2.5.4.3` is CN).
            let oid: String
            /// The text value, nil when the value is not a string type.
            let value: String?
            /// The value element as encoded.
            let valueDER: Data
        }

        /// The Name as encoded (what issuer/subject comparisons use).
        let der: Data
        /// Relative distinguished names in encoding order (most general first).
        let rdns: [[Attribute]]

        /// Every attribute in encoding order.
        var attributes: [Attribute] { rdns.flatMap { $0 } }

        /// The most specific CN — the first one in the RFC 2253 form, which
        /// is where `subjectX500Principal.name.substringAfter("CN=")` finds it.
        var commonName: String? {
            attributes.last { $0.oid == X509OID.commonName }?.value
        }

        /// RFC 2253 text, as `X500Principal.getName()` prints it: most
        /// specific RDN first, `,` between RDNs, `+` inside one.
        var rfc2253: String {
            rdns.reversed().map { rdn in
                rdn.map { attribute in
                    if let short = X509OID.shortNames[attribute.oid], let value = attribute.value {
                        return short + "=" + Self.escape(value)
                    }
                    return attribute.oid + "=#" + Hex.encode(attribute.valueDER)
                }.joined(separator: "+")
            }.joined(separator: ",")
        }

        private static func escape(_ value: String) -> String {
            var out = ""
            for (index, character) in value.enumerated() {
                let first = index == 0
                let last = index == value.count - 1
                if ",+\"\\<>;".contains(character) || (first && (character == "#" || character == " ")) || (last && character == " ") {
                    out.append("\\")
                }
                out.append(character)
            }
            return out
        }

        init(der: Data) throws {
            self.der = der
            let sets = try DER.parse(der).expect(ASN1Tag.sequence).children()
            rdns = try sets.map { set in
                try set.expect(ASN1Tag.set).children().map { pair in
                    let parts = try pair.expect(ASN1Tag.sequence).children()
                    guard parts.count == 2 else { throw DERError.invalidValue("malformed AttributeTypeAndValue") }
                    let oid = try parts[0].expect(ASN1Tag.objectIdentifier).objectIdentifier()
                    return Attribute(oid: oid, value: try? parts[1].string(), valueDER: parts[1].encoded)
                }
            }
        }
    }

    /// One entry of a GeneralNames sequence (subjectAltName).
    enum GeneralName: Sendable, Equatable {
        case dnsName(String)
        case ipAddress(Data)
        case uri(String)
        case email(String)
        case other(tag: UInt8, encoded: Data)
    }

    /// One extension, as encoded.
    struct Extension: Sendable, Equatable {
        let oid: String
        let critical: Bool
        /// The extnValue OCTET STRING content (itself DER).
        let value: Data
    }

    /// keyUsage bits (RFC 5280 §4.2.1.3).
    struct KeyUsage: OptionSet, Sendable, Equatable {
        let rawValue: UInt16
        static let digitalSignature = KeyUsage(rawValue: 1 << 0)
        static let nonRepudiation = KeyUsage(rawValue: 1 << 1)
        static let keyEncipherment = KeyUsage(rawValue: 1 << 2)
        static let dataEncipherment = KeyUsage(rawValue: 1 << 3)
        static let keyAgreement = KeyUsage(rawValue: 1 << 4)
        static let keyCertSign = KeyUsage(rawValue: 1 << 5)
        static let cRLSign = KeyUsage(rawValue: 1 << 6)
        static let encipherOnly = KeyUsage(rawValue: 1 << 7)
        static let decipherOnly = KeyUsage(rawValue: 1 << 8)
    }

    /// The whole certificate.
    let der: Data
    /// The `tbsCertificate` element (tag and length included): what the signature covers.
    let tbsCertificate: Data
    /// 1, 2 or 3.
    let version: Int
    /// The serial number INTEGER content as encoded (two's complement).
    let serialNumber: Data
    /// The signature algorithm named inside the tbsCertificate.
    let tbsSignatureAlgorithmOID: String
    let issuer: Name
    let subject: Name
    let notBefore: Date
    let notAfter: Date
    /// The SubjectPublicKeyInfo element, as encoded: what pins are over.
    let subjectPublicKeyInfo: Data
    let extensions: [Extension]
    /// The outer signatureAlgorithm.
    let signatureAlgorithmOID: String
    /// The signature BIT STRING bytes (DER ECDSA-Sig-Value for ECDSA).
    let signature: Data

    init(der: Data) throws {
        self.der = der
        let outer = try DER.parse(der).expect(ASN1Tag.sequence).children()
        guard outer.count == 3 else { throw DERError.invalidValue("Certificate must have three parts") }
        let tbs = try outer[0].expect(ASN1Tag.sequence)
        tbsCertificate = tbs.encoded
        signatureAlgorithmOID = try Self.algorithmOID(outer[1])
        signature = try outer[2].expect(ASN1Tag.bitString).bitStringBytes()

        var fields = try tbs.children()[...]
        var version = 1
        if let first = fields.first, first.tag == ASN1Tag.contextSpecific(0, constructed: true) {
            version = try first.explicitInner().expect(ASN1Tag.integer).intValue() + 1
            fields = fields.dropFirst()
        }
        guard (1...3).contains(version) else { throw DERError.invalidValue("unknown certificate version \(version)") }
        self.version = version
        guard fields.count >= 6 else { throw DERError.invalidValue("tbsCertificate is missing fields") }
        let items = Array(fields)
        serialNumber = try items[0].expect(ASN1Tag.integer).integerBytes()
        tbsSignatureAlgorithmOID = try Self.algorithmOID(items[1])
        issuer = try Name(der: items[2].expect(ASN1Tag.sequence).encoded)
        let validity = try items[3].expect(ASN1Tag.sequence).children()
        guard validity.count == 2 else { throw DERError.invalidValue("malformed Validity") }
        notBefore = try validity[0].time()
        notAfter = try validity[1].time()
        subject = try Name(der: items[4].expect(ASN1Tag.sequence).encoded)
        subjectPublicKeyInfo = try items[5].expect(ASN1Tag.sequence).encoded

        var extensions: [Extension] = []
        for element in items.dropFirst(6) where element.tag == ASN1Tag.contextSpecific(3, constructed: true) {
            for ext in try element.explicitInner().expect(ASN1Tag.sequence).children() {
                let parts = try ext.expect(ASN1Tag.sequence).children()
                guard parts.count == 2 || parts.count == 3 else { throw DERError.invalidValue("malformed Extension") }
                let oid = try parts[0].expect(ASN1Tag.objectIdentifier).objectIdentifier()
                var critical = false
                if parts.count == 3 { critical = try parts[1].expect(ASN1Tag.boolean).boolean() }
                let value = try parts[parts.count - 1].expect(ASN1Tag.octetString).octetString()
                extensions.append(Extension(oid: oid, critical: critical, value: value))
            }
        }
        self.extensions = extensions
    }

    /// The certificate inside a `SecCertificate`.
    init(certificate: SecCertificate) throws {
        try self.init(der: SecCertificateCopyData(certificate) as Data)
    }

    /// The first certificate of a PEM text.
    init(pem: String) throws {
        guard let der = PEM.decode(pem, label: "CERTIFICATE") else {
            throw DERError.invalidValue("no CERTIFICATE block in the PEM text")
        }
        try self.init(der: der)
    }

    /// Every certificate of the PEM texts, in order (`Pkcs10Csr.parsePemChain`).
    static func parsePEMChain(_ pems: [String]) throws -> [X509Certificate] {
        try pems.flatMap { pem in
            try PEM.decodeAll(pem).filter { $0.label == "CERTIFICATE" }.map { try X509Certificate(der: $0.der) }
        }
    }

    /// A `SecCertificate` for these bytes; nil when Security refuses them.
    func secCertificate() -> SecCertificate? {
        SecCertificateCreateWithData(nil, der as CFData)
    }

    /// Base64(SHA-256(SPKI)) — the pin of this certificate's key.
    var spkiPin: String { SPKI.pin(subjectPublicKeyInfo) }

    func isValid(at date: Date) -> Bool {
        date >= notBefore && date <= notAfter
    }

    func `extension`(_ oid: String) -> Extension? {
        extensions.first { $0.oid == oid }
    }

    /// The subjectAltName entries; empty without the extension (or when it is malformed).
    var subjectAltNames: [GeneralName] {
        guard let ext = `extension`(X509OID.subjectAltName),
              let names = try? DER.parse(ext.value).expect(ASN1Tag.sequence).children() else { return [] }
        return names.map { name in
            switch name.tag {
            case ASN1Tag.contextSpecific(2, constructed: false):
                return String(data: name.content, encoding: .ascii).map(GeneralName.dnsName) ?? .other(tag: name.tag, encoded: name.encoded)
            case ASN1Tag.contextSpecific(7, constructed: false):
                return .ipAddress(name.content)
            case ASN1Tag.contextSpecific(6, constructed: false):
                return String(data: name.content, encoding: .ascii).map(GeneralName.uri) ?? .other(tag: name.tag, encoded: name.encoded)
            case ASN1Tag.contextSpecific(1, constructed: false):
                return String(data: name.content, encoding: .ascii).map(GeneralName.email) ?? .other(tag: name.tag, encoded: name.encoded)
            default:
                return .other(tag: name.tag, encoded: name.encoded)
            }
        }
    }

    /// SAN dNSName entries.
    var dnsNames: [String] {
        subjectAltNames.compactMap { if case .dnsName(let name) = $0 { return name } else { return nil } }
    }

    /// SAN iPAddress entries, raw (4 or 16 bytes).
    var ipAddresses: [Data] {
        subjectAltNames.compactMap { if case .ipAddress(let address) = $0 { return address } else { return nil } }
    }

    /// SAN iPAddress entries as text (`192.168.1.10`, `fe80::1`).
    var ipAddressStrings: [String] {
        ipAddresses.compactMap(Self.ipString)
    }

    /// basicConstraints: nil without the extension.
    var basicConstraints: (isCA: Bool, pathLength: Int?)? {
        guard let ext = `extension`(X509OID.basicConstraints),
              let parts = try? DER.parse(ext.value).expect(ASN1Tag.sequence).children() else { return nil }
        var isCA = false
        var pathLength: Int?
        for part in parts {
            if part.tag == ASN1Tag.boolean { isCA = (try? part.boolean()) ?? false }
            if part.tag == ASN1Tag.integer { pathLength = try? part.intValue() }
        }
        return (isCA, pathLength)
    }

    /// True when basicConstraints says cA.
    var isCA: Bool { basicConstraints?.isCA ?? false }

    /// keyUsage: nil without the extension.
    var keyUsage: KeyUsage? {
        guard let ext = `extension`(X509OID.keyUsage),
              let bits = try? DER.parse(ext.value).expect(ASN1Tag.bitString).bitString() else { return nil }
        var raw: UInt16 = 0
        for (byteIndex, byte) in bits.bytes.prefix(2).enumerated() {
            for bit in 0..<8 where byte & (0x80 >> bit) != 0 {
                raw |= 1 << UInt16(byteIndex * 8 + bit)
            }
        }
        return KeyUsage(rawValue: raw)
    }

    /// extendedKeyUsage purposes, dotted; empty without the extension.
    var extendedKeyUsage: [String] {
        guard let ext = `extension`(X509OID.extendedKeyUsage),
              let purposes = try? DER.parse(ext.value).expect(ASN1Tag.sequence).children() else { return [] }
        return purposes.compactMap { try? $0.objectIdentifier() }
    }

    private static func algorithmOID(_ element: DERElement) throws -> String {
        let parts = try element.expect(ASN1Tag.sequence).children()
        guard let first = parts.first else { throw DERError.invalidValue("empty AlgorithmIdentifier") }
        return try first.expect(ASN1Tag.objectIdentifier).objectIdentifier()
    }

    static func ipString(_ address: Data) -> String? {
        var bytes = [UInt8](address)
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let family: Int32
        switch bytes.count {
        case 4: family = AF_INET
        case 16: family = AF_INET6
        default: return nil
        }
        guard inet_ntop(family, &bytes, &buffer, socklen_t(buffer.count)) != nil else { return nil }
        return String(decoding: buffer.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }
}

/// OIDs of the certificate fields and extensions the parser reads.
enum X509OID {
    static let commonName = "2.5.4.3"
    static let subjectAltName = "2.5.29.17"
    static let basicConstraints = "2.5.29.19"
    static let keyUsage = "2.5.29.15"
    static let extendedKeyUsage = "2.5.29.37"
    static let subjectKeyIdentifier = "2.5.29.14"
    static let authorityKeyIdentifier = "2.5.29.35"
    static let ecdsaWithSHA256 = "1.2.840.10045.4.3.2"
    static let sha256WithRSAEncryption = "1.2.840.113549.1.1.11"

    /// RFC 2253 keywords (the ones `X500Principal` prints by name).
    static let shortNames: [String: String] = [
        "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O",
        "2.5.4.11": "OU", "2.5.4.9": "STREET", "0.9.2342.19200300.100.1.25": "DC",
        "0.9.2342.19200300.100.1.1": "UID",
    ]
}
