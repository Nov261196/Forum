document.addEventListener('DOMContentLoaded', () => {
    const themeToggleBtn = document.getElementById('theme-toggle');
    const body = document.body;

    // Lấy theme đã lưu từ localStorage (nếu có), mặc định là 'light-mode'
    const currentTheme = localStorage.getItem('theme') || 'light-mode';
    body.classList.add(currentTheme);

    // Cập nhật icon dựa trên theme hiện tại
    updateThemeIcon(currentTheme);

    themeToggleBtn.addEventListener('click', () => {
        if (body.classList.contains('light-mode')) {
            body.classList.remove('light-mode');
            body.classList.add('dark-mode');
            localStorage.setItem('theme', 'dark-mode');
            updateThemeIcon('dark-mode');
        } else {
            body.classList.remove('dark-mode');
            body.classList.add('light-mode');
            localStorage.setItem('theme', 'light-mode');
            updateThemeIcon('light-mode');
        }
    });

    function updateThemeIcon(theme) {
        if (theme === 'dark-mode') {
            themeToggleBtn.innerHTML = '<i class="fas fa-sun"></i>'; // Icon mặt trời cho Light mode
            themeToggleBtn.title = 'Chuyển sang chế độ sáng';
        } else {
            themeToggleBtn.innerHTML = '<i class="fas fa-moon"></i>'; // Icon mặt trăng cho Dark mode
            themeToggleBtn.title = 'Chuyển sang chế độ tối';
        }
    }
});