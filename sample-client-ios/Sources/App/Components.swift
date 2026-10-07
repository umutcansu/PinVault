import SwiftUI
import UIKit

// Ekran parçaları. Her öğenin accessibilityIdentifier'ı Android düzenindeki görünüm
// kimliğidir (statusView, testButton, tokenInput, …): sample-e2e iOS'ta öğeleri
// XCUITest erişilebilirlik ağacından bu kimlikle bulur (lib/ios.js). Metin kutuları
// bütün metni etiket olarak verir; alanlar metni değer olarak; onay kutuları ve
// radyo düğmeleri değer olarak "1"/"0".

/// Çok satırlı metin kutusu (Android: TextView). Etiket bütün metindir.
struct StatusText: View {
    let id: String
    let text: String
    var minHeight: CGFloat = 0
    var bold = false

    var body: some View {
        Text(verbatim: text)
            .font(bold ? .callout.weight(.semibold) : .footnote)
            .frame(maxWidth: .infinity, minHeight: minHeight, alignment: .topLeading)
            .fixedSize(horizontal: false, vertical: true)
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(Text(verbatim: text))
            .accessibilityIdentifier(id)
    }
}

/// Kalın başlık satırı (kimliksiz; Android'de de kimliği yok).
struct SectionTitle: View {
    let text: String

    var body: some View {
        Text(verbatim: text)
            .font(.subheadline.weight(.bold))
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 6)
    }
}

/// Düğme (Android: Button). Etiket başlıktır, etkinlik `isEnabled`.
struct ActionButton: View {
    let id: String
    let title: String
    var enabled = true
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(verbatim: title)
                .font(.subheadline)
                .multilineTextAlignment(.center)
                .frame(maxWidth: .infinity, minHeight: 30)
        }
        .buttonStyle(.bordered)
        .disabled(!enabled)
        .accessibilityLabel(Text(verbatim: title))
        .accessibilityIdentifier(id)
    }
}

/// Tek satırlık giriş alanı (Android: EditText). [secure]: parola alanı
/// (textPassword); değeri erişilebilirlik ağacında "•" dizisidir.
struct InputField: View {
    let id: String
    let hint: String
    @Binding var text: String
    var secure = false
    var enabled = true
    var keyboard: UIKeyboardType = .default

    var body: some View {
        Group {
            if secure {
                SecureField(hint, text: $text)
            } else {
                TextField(hint, text: $text)
            }
        }
        .textFieldStyle(.roundedBorder)
        .textInputAutocapitalization(.never)
        .autocorrectionDisabled()
        .keyboardType(keyboard)
        .textContentType(nil)
        .submitLabel(.done)
        .disabled(!enabled)
        .accessibilityIdentifier(id)
    }
}

/// Onay kutusu (Android: CheckBox). Düğme olarak çizilir: dokunuş her yerde çevirir;
/// değeri "1" (işaretli) ya da "0".
struct CheckBox: View {
    let id: String
    let title: String
    @Binding var isOn: Bool
    var enabled = true

    var body: some View {
        Button {
            isOn.toggle()
        } label: {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Image(systemName: isOn ? "checkmark.square.fill" : "square").accessibilityHidden(true)
                Text(verbatim: title).multilineTextAlignment(.leading)
                Spacer(minLength: 0)
            }
            .font(.subheadline)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(!enabled)
        .accessibilityLabel(Text(verbatim: title))
        .accessibilityValue(Text(verbatim: isOn ? "1" : "0"))
        .accessibilityAddTraits(isOn ? .isSelected : [])
        .accessibilityIdentifier(id)
    }
}

/// Radyo düğmesi (Android: RadioButton). Değeri "1" (seçili) ya da "0".
struct RadioButton: View {
    let id: String
    let title: String
    let selected: Bool
    let select: () -> Void

    var body: some View {
        Button(action: select) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Image(systemName: selected ? "largecircle.fill.circle" : "circle").accessibilityHidden(true)
                Text(verbatim: title).multilineTextAlignment(.leading)
                Spacer(minLength: 0)
            }
            .font(.subheadline)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(Text(verbatim: title))
        .accessibilityValue(Text(verbatim: selected ? "1" : "0"))
        .accessibilityAddTraits(selected ? .isSelected : [])
        .accessibilityIdentifier(id)
    }
}

/// Ekranın kaydırılabilir gövdesi.
struct ScreenBody<Content: View>: View {
    @ViewBuilder let content: () -> Content

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 8) {
                content()
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
        }
        .scrollDismissesKeyboard(.interactively)
    }
}

extension View {
    /// Alt ekranların ortak çerçevesi: başlık, `backButton` (iOS'ta sistem geri tuşu
    /// yok; sample-e2e "geri"yi bu kimlikle basar) ve klavye çubuğunda "Bitti"
    /// (`keyboardDoneButton`).
    func screenChrome(_ title: String) -> some View {
        modifier(ScreenChrome(title: title))
    }

    /// Klavye çubuğunda "Bitti" (`keyboardDoneButton`).
    func keyboardDoneBar() -> some View {
        toolbar {
            ToolbarItemGroup(placement: .keyboard) {
                Spacer()
                Button(S.keyboardDone) { dismissKeyboard() }
                    .accessibilityIdentifier("keyboardDoneButton")
            }
        }
    }
}

@MainActor
func dismissKeyboard() {
    UIApplication.shared.sendAction(#selector(UIResponder.resignFirstResponder), to: nil, from: nil, for: nil)
}

private struct ScreenChrome: ViewModifier {
    let title: String
    @Environment(\.dismiss) private var dismiss

    func body(content: Content) -> some View {
        content
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .navigationBarBackButtonHidden(true)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button {
                        dismissKeyboard()
                        dismiss()
                    } label: {
                        HStack(spacing: 3) {
                            Image(systemName: "chevron.left").accessibilityHidden(true)
                            Text(verbatim: S.back)
                        }
                    }
                    .accessibilityLabel(Text(verbatim: S.back))
                    .accessibilityIdentifier("backButton")
                }
            }
            .keyboardDoneBar()
    }
}
