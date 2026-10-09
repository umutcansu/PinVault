import 'package:flutter/material.dart';
import 'package:pinvault_flutter/pinvault_flutter.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'PinVault Demo',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.deepPurple),
        useMaterial3: true,
      ),
      home: const MyHomePage(title: 'PinVault Flutter Plugin'),
    );
  }
}

class MyHomePage extends StatefulWidget {
  const MyHomePage({super.key, required this.title});
  final String title;

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  String _status = 'Not Started';

  Future<void> _initPinVault() async {
    try {
      final config = PinVaultConfig(
        configApis: [
          ConfigApiBlock(
            id: 'demo-api',
            url: 'https://demo.pinvault.example.com',
            // Normally provide pins, but let's test the bridge
          )
        ],
      );
      
      final result = await PinVault.start(config);
      setState(() {
        _status = 'Started: \${result['type']}';
      });
    } catch (e) {
      setState(() {
        _status = 'Error: \$e';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        title: Text(widget.title),
      ),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            Text('PinVault Status:'),
            Text(
              _status,
              style: Theme.of(context).textTheme.headlineMedium,
            ),
          ],
        ),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: _initPinVault,
        tooltip: 'Initialize',
        child: const Icon(Icons.security),
      ),
    );
  }
}
