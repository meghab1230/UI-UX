// document.addEventListener('DOMContentLoaded', (event) => {
//     let currentSlide = 0;
  
//     function showSlide(index) {
//       const slides = document.querySelectorAll('.carousel-item');
//       if (index >= slides.length) currentSlide = 0;
//       if (index < 0) currentSlide = slides.length - 1;
  
//       const offset = -currentSlide * 100;
//       document.querySelector('.carousel-inner').style.transform = `translateX(${offset}%)`;
  
//       slides.forEach((slide, i) => {
//         slide.classList.toggle('active', i === currentSlide);
//       });
//     }
  
//     function nextSlide() {
//       currentSlide++;
//       showSlide(currentSlide);
//     }
  
//     function prevSlide() {
//       currentSlide--;
//       showSlide(currentSlide);
//     }
  
//     // Auto slide
//     setInterval(() => {
//       nextSlide();
//     }, 3000); // Change slide every 3 seconds
  
//     document.querySelector('.carousel-control-next').addEventListener('click', nextSlide);
//     document.querySelector('.carousel-control-prev').addEventListener('click', prevSlide);
//   });
  