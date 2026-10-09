library pinvault_flutter;

import 'package:flutter/services.dart';
import 'src/types.dart';
import 'src/pinvault_websocket.dart';

export 'src/types.dart';
export 'src/pinvault_websocket.dart';

/// PinVault Flutter API Bridge
class PinVault {
  static const MethodChannel _channel = MethodChannel('pinvault_flutter');

  /// Starts PinVault with the given configuration object.
  static Future<Map<String, dynamic>> start(PinVaultConfig config) async {
    final result = await _channel.invokeMethod('start', config.toJson());
    return Map<String, dynamic>.from(result);
  }

  /// Initiates a fetch request using the native pinned client.
  static Future<Map<String, dynamic>> fetch(String url, {Map<String, dynamic>? options}) async {
    final result = await _channel.invokeMethod('fetch', {
      'url': url,
      'options': options ?? {},
    });
    return Map<String, dynamic>.from(result);
  }
}
