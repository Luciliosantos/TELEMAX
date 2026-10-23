// TELEMAX — interações leves
document.addEventListener('DOMContentLoaded', function () {
  var t = document.getElementById('navToggle');
  if (t) t.addEventListener('click', function () {
    document.getElementById('mainNav').classList.toggle('open');
  });
  // Categorias abre/fecha ao toque ou clique
  document.querySelectorAll('.nav-drop-btn').forEach(function (b) {
    b.addEventListener('click', function () {
      b.parentElement.classList.toggle('open');
    });
  });
  document.querySelectorAll('[data-copy]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var el = document.querySelector(btn.getAttribute('data-copy'));
      if (!el) return;
      el.select();
      navigator.clipboard && navigator.clipboard.writeText(el.value);
      var old = btn.textContent;
      btn.textContent = '✓ Copiado!';
      setTimeout(function () { btn.textContent = old; }, 1800);
    });
  });

  // Carrossel automático de banners: troca a cada 5 segundos.
  document.querySelectorAll('[data-banner-carousel]').forEach(function (carousel) {
    var slides = Array.prototype.slice.call(carousel.querySelectorAll('.banner'));
    if (!slides.length) return;

    var current = 0;
    slides.forEach(function (slide, index) {
      slide.classList.toggle('is-active', index === 0);
    });

    if (slides.length < 2) return;

    window.setInterval(function () {
      slides[current].classList.remove('is-active');
      current = (current + 1) % slides.length;
      slides[current].classList.add('is-active');
    }, 5000);
  });
});
