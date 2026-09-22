// Swagger UI başlatma.
//
// Ayrı dosyada duruyor çünkü sunucunun CSP'si `script-src 'self'` — inline
// <script> bloğu (eski docs.html'deki gibi) tarayıcı tarafından engelleniyor
// ve sayfa boş açılıyordu. CSP'yi gevşetmek yerine kod aynı origin'den
// yükleniyor.
window.addEventListener('DOMContentLoaded', function () {
  SwaggerUIBundle({
    url: '/static/openapi.yaml',
    dom_id: '#swagger-ui',
    deepLinking: true,
    // Standalone preset yüklenmiyor (topbar'a ihtiyaç yok), bu yüzden
    // BaseLayout kullanılıyor.
    presets: [SwaggerUIBundle.presets.apis],
    layout: 'BaseLayout',
    docExpansion: 'none',
    defaultModelsExpandDepth: 0,
    tryItOutEnabled: true
  });
});
