// A wss:// echo server for integration_test/demo_server_test.dart's WebSocket
// test. It first sends "x-test=<the X-Test header it got>", then echoes text and
// binary frames; the text "close-me" makes it close (4000 "bye").
//
//   cd scripts && sh wss_echo_server.sh      (makes a certificate, prints its pin)
import 'dart:io';

Future<void> main(List<String> args) async {
  final port = int.parse(args.isEmpty ? '8765' : args[0]);
  final context = SecurityContext()
    ..useCertificateChain('wss-cert.pem')
    ..usePrivateKey('wss-key.pem');
  final server = await HttpServer.bindSecure(InternetAddress.anyIPv4, port, context);
  stdout.writeln('wss echo on $port');
  await for (final request in server) {
    if (!WebSocketTransformer.isUpgradeRequest(request)) {
      request.response.statusCode = 404;
      await request.response.close();
      continue;
    }
    // OkHttp refuses the extension parameters dart:io answers with.
    final socket = await WebSocketTransformer.upgrade(request, compression: CompressionOptions.compressionOff);
    final header = request.headers.value('x-test') ?? '';
    stdout.writeln('open $header');
    socket.add('x-test=$header');
    socket.listen((frame) {
      if (frame == 'close-me') {
        socket.close(4000, 'bye');
      } else {
        socket.add(frame);
      }
    }, onDone: () => stdout.writeln('closed ${socket.closeCode}'));
  }
}
