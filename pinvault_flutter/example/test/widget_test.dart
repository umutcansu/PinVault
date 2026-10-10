import 'package:flutter_test/flutter_test.dart';

import 'package:example/main.dart';

void main() {
  testWidgets('PinVault demo renders the start screen', (WidgetTester tester) async {
    await tester.pumpWidget(const MyApp());

    expect(find.text('PinVault Flutter Plugin'), findsOneWidget);
    expect(find.text('Not Started'), findsOneWidget);
    expect(find.text('Start'), findsOneWidget);
  });
}
