document.addEventListener('DOMContentLoaded', () => {
    const newPasswordInput = document.getElementById('new-password');
    const confirmNewPasswordInput = document.getElementById('confirm-new-password');
    const submitResetButton = document.getElementById('submit-reset-password');
    const resetMessage = document.getElementById('reset-message');

    // Lấy token từ URL (ví dụ: http://localhost:5500/reset-password.html?token=YOUR_TOKEN)
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');

    // Nếu không có token, hiển thị lỗi và không cho phép reset
    if (!token) {
        resetMessage.textContent = 'Token đặt lại mật khẩu không tìm thấy trong URL.';
        resetMessage.style.color = 'red';
        submitResetButton.disabled = true; // Vô hiệu hóa nút
        return; // Dừng script
    }

    submitResetButton.addEventListener('click', async () => {
        const newPassword = newPasswordInput.value;
        const confirmNewPassword = confirmNewPasswordInput.value;

        // Xóa thông báo cũ
        resetMessage.textContent = '';
        resetMessage.style.color = '';

        if (!newPassword || !confirmNewPassword) {
            resetMessage.textContent = 'Vui lòng nhập cả mật khẩu mới và xác nhận mật khẩu.';
            resetMessage.style.color = 'red';
            return;
        }

        if (newPassword !== confirmNewPassword) {
            resetMessage.textContent = 'Mật khẩu mới và xác nhận mật khẩu không khớp.';
            resetMessage.style.color = 'red';
            return;
        }

        // Gửi yêu cầu đặt lại mật khẩu đến backend
        try {
            const response = await fetch('http://localhost:3000/api/reset-password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ token, newPassword })
            });

            const data = await response.json();

            if (response.ok) {
                resetMessage.textContent = data.message;
                resetMessage.style.color = 'green';
                // Tùy chọn: Chuyển hướng người dùng về trang đăng nhập sau vài giây
                setTimeout(() => {
                    window.location.href = 'index.html'; // Hoặc URL của trang đăng nhập
                }, 3000);
            } else {
                resetMessage.textContent = data.message || 'Đã xảy ra lỗi khi đặt lại mật khẩu.';
                resetMessage.style.color = 'red';
            }
        } catch (error) {
            console.error('Lỗi khi gửi yêu cầu reset mật khẩu:', error);
            resetMessage.textContent = 'Đã xảy ra lỗi mạng hoặc máy chủ không phản hồi.';
            resetMessage.style.color = 'red';
        }
    });
});