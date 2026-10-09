class PinVaultConfig {
  final List<ConfigApiBlock> configApis;
  final List<String>? requireCaTrust;
  final bool? requireUnlockedDevice;
  final bool? requireHardwareBackedKeys;
  
  PinVaultConfig({
    required this.configApis,
    this.requireCaTrust,
    this.requireUnlockedDevice,
    this.requireHardwareBackedKeys,
  });

  Map<String, dynamic> toJson() {
    return {
      'configApis': configApis.map((e) => e.toJson()).toList(),
      if (requireCaTrust != null) 'requireCaTrust': requireCaTrust,
      if (requireUnlockedDevice != null) 'requireUnlockedDevice': requireUnlockedDevice,
      if (requireHardwareBackedKeys != null) 'requireHardwareBackedKeys': requireHardwareBackedKeys,
    };
  }
}

class ConfigApiBlock {
  final String id;
  final String url;
  final List<HostPin>? bootstrapPins;
  final String? serverScope;
  final List<String>? signaturePublicKeys;
  final int? requiredSignatures;

  ConfigApiBlock({
    required this.id,
    required this.url,
    this.bootstrapPins,
    this.serverScope,
    this.signaturePublicKeys,
    this.requiredSignatures,
  });

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'url': url,
      if (bootstrapPins != null) 'bootstrapPins': bootstrapPins!.map((e) => e.toJson()).toList(),
      if (serverScope != null) 'serverScope': serverScope,
      if (signaturePublicKeys != null) 'signaturePublicKeys': signaturePublicKeys,
      if (requiredSignatures != null) 'requiredSignatures': requiredSignatures,
    };
  }
}

class HostPin {
  final String hostname;
  final List<String> sha256;

  HostPin({
    required this.hostname,
    required this.sha256,
  });

  Map<String, dynamic> toJson() {
    return {
      'hostname': hostname,
      'sha256': sha256,
    };
  }
}
