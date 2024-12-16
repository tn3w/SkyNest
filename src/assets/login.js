document.addEventListener('DOMContentLoaded', () => {
    const passwordInput = document.getElementById('password');
    const togglePassword = document.getElementById('toggle-password');
    const eyeIcon = document.getElementById('eye-icon');

    const eyeOpenSVG = `
      <path d="M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0" fill="var(--button-hover)"/>
      <path d="M21.894 11.553C19.736 7.236 15.904 5 12 5s-7.736 2.236-9.894 6.553a1 1 0 0 0 0 .894C4.264 16.764 8.096 19 12 19s7.736-2.236 9.894-6.553a1 1 0 0 0 0-.894M12 17c-2.969 0-6.002-1.62-7.87-5C5.998 8.62 9.03 7 12 7s6.002 1.62 7.87 5c-1.868 3.38-4.901 5-7.87 5" fill="var(--button-hover)"/>
    `;

    const eyeClosedSVG = `
      <path d="M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0" fill="var(--button-hover)"/>
      <path d="M21.894 11.553C19.736 7.236 15.904 5 12 5s-7.736 2.236-9.894 6.553a1 1 0 0 0 0 .894C4.264 16.764 8.096 19 12 19s7.736-2.236 9.894-6.553a1 1 0 0 0 0-.894M12 17c-2.969 0-6.002-1.62-7.87-5C5.998 8.62 9.03 7 12 7s6.002 1.62 7.87 5c-1.868 3.38-4.901 5-7.87 5" fill="var(--button-hover)"/>
      <path d="M4 4l16 16" stroke="var(--button-hover)" stroke-width="2" stroke-linecap="round"/>
    `;

    let isPasswordVisible = false;

    togglePassword.addEventListener('click', () => {
        isPasswordVisible = !isPasswordVisible;
        passwordInput.type = isPasswordVisible ? 'text' : 'password';
        eyeIcon.innerHTML = isPasswordVisible ? eyeClosedSVG : eyeOpenSVG;
    });
});