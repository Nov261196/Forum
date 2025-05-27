document.addEventListener('DOMContentLoaded', () => {
    // ------------------- Elements for Register Form -------------------
    const registerFirstNameInput = document.getElementById('reg-first-name');
    const registerLastNameInput = document.getElementById('reg-last-name');
    const registerEmailInput = document.getElementById('reg-email');
    const registerPasswordInput = document.getElementById('reg-password');
    const registerConfirmPasswordInput = document.getElementById('reg-confirm-password');
    const registerPhoneNumberInput = document.getElementById('reg-phone-number');
    const registerButton = document.getElementById('register-button');
    const registerMessage = document.getElementById('register-message'); // Để hiển thị thông báo

    // ------------------- Elements for Login Form -------------------
    const loginEmailInput = document.getElementById('login-email');
    const loginPasswordInput = document.getElementById('login-password');
    const loginButton = document.getElementById('login-button');
    const loginMessage = document.getElementById('login-message'); // Có thể cần thêm id này trong HTML nếu muốn dùng

    // ------------------- Elements for Forgot Password Form -------------------
    const forgotEmailInput = document.getElementById('forgot-email');
    const resetPasswordButton = document.getElementById('reset-password-button');
    const forgotMessage = document.getElementById('forgot-message'); // Để hiển thị thông báo

    // ------------------- Toggle Forms Logic (sử dụng checkbox đã có) -------------------
    // Đảm bảo CSS của bạn xử lý việc hiển thị/ẩn các form dựa trên checkbox toggle-form và toggle-forgot
    // (Bạn đã có CSS này, chỉ cần chắc chắn nó hoạt động đúng)

    // Hàm hiển thị thông báo
    const displayMessage = (element, msg, isError = false) => {
        element.textContent = msg;
        element.style.color = isError ? 'red' : 'green';
    };

    // ------------------- Register Logic -------------------
    if (registerButton) { // Kiểm tra để đảm bảo nút tồn tại
        registerButton.addEventListener('click', async (e) => {
            e.preventDefault(); // Ngăn form gửi đi theo cách truyền thống

            // Xóa thông báo cũ
            if (registerMessage) registerMessage.textContent = '';

            // Lấy giá trị từ các trường input
            // Lưu ý: Backend của bạn hiện chỉ nhận username, email, password.
            // first_name, last_name, phone_number không được xử lý ở backend hiện tại.
            // Bạn sẽ cần cập nhật backend và DB nếu muốn lưu trữ chúng.
            const username = registerFirstNameInput.value.trim() + ' ' + registerLastNameInput.value.trim(); // Ghép First & Last Name thành username
            const email = registerEmailInput.value.trim();
            const password = registerPasswordInput.value.trim();
            const confirmPassword = registerConfirmPasswordInput.value.trim();
            // const phoneNumber = registerPhoneNumberInput.value.trim(); // Nếu bạn muốn dùng sau này

            // Basic Client-side Validation
            if (!username || !email || !password || !confirmPassword) {
                if (registerMessage) displayMessage(registerMessage, 'Vui lòng điền đầy đủ thông tin.', true);
                return;
            }

            if (password !== confirmPassword) {
                if (registerMessage) displayMessage(registerMessage, 'Mật khẩu xác nhận không khớp.', true);
                return;
            }

            // Gửi request đến backend
            try {
                const response = await fetch('http://localhost:3000/api/register', { // Đảm bảo URL backend đúng
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ username, email, password }), // Chỉ gửi các trường mà backend xử lý
                });

                const data = await response.json();

                if (response.ok) { // Status 2xx
                    if (registerMessage) displayMessage(registerMessage, data.message);
                    // Sau khi đăng ký thành công, bạn có thể chuyển hướng người dùng hoặc hiển thị form đăng nhập
                    document.getElementById('toggle-form').checked = false; // Chuyển sang form Login
                } else { // Status 4xx, 5xx
                    if (registerMessage) displayMessage(registerMessage, data.message || 'Đã xảy ra lỗi khi đăng ký.', true);
                }
            } catch (err) {
                console.error('Lỗi mạng hoặc kết nối server:', err);
                if (registerMessage) displayMessage(registerMessage, 'Không thể kết nối đến máy chủ. Vui lòng thử lại sau.', true);
            }
        });
    }

    // ------------------- Login Logic (Tương tự như Register) -------------------
    if (loginButton) {
        loginButton.addEventListener('click', async (e) => {
            e.preventDefault();

            if (loginMessage) loginMessage.textContent = ''; // Clear message

            const email = loginEmailInput.value.trim();
            const password = loginPasswordInput.value.trim();

            if (!email || !password) {
                if (loginMessage) displayMessage(loginMessage, 'Vui lòng nhập email và mật khẩu.', true);
                return;
            }

            try {
                const response = await fetch('http://localhost:3000/api/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ email, password }),
                });

                const data = await response.json();

                if (response.ok) {
                    if (loginMessage) displayMessage(loginMessage, data.message);
                    // Lưu token vào localStorage hoặc sessionStorage
                    localStorage.setItem('token', data.token);
                    // Chuyển hướng người dùng đến trang khác (ví dụ: trang chủ)
                    // window.location.href = '/dashboard.html';
                } else {
                    if (loginMessage) displayMessage(loginMessage, data.message || 'Đã xảy ra lỗi khi đăng nhập.', true);
                }
            } catch (err) {
                console.error('Lỗi mạng hoặc kết nối server:', err);
                if (loginMessage) displayMessage(loginMessage, 'Không thể kết nối đến máy chủ. Vui lòng thử lại sau.', true);
            }
        });
    }

    // ------------------- Forgot Password Logic -------------------
    if (resetPasswordButton) {
        resetPasswordButton.addEventListener('click', async (e) => {
            e.preventDefault();

            if (forgotMessage) forgotMessage.textContent = '';

            const email = forgotEmailInput.value.trim();

            if (!email) {
                if (forgotMessage) displayMessage(forgotMessage, 'Vui lòng nhập email.', true);
                return;
            }

            try {
                const response = await fetch('http://localhost:3000/api/forgot-password', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ email }),
                });

                const data = await response.json();

                if (response.ok) {
                    // Mặc dù thành công, thông báo nên chung chung để tránh lộ email
                    if (forgotMessage) displayMessage(forgotMessage, data.message);
                } else {
                    if (forgotMessage) displayMessage(forgotMessage, data.message || 'Đã xảy ra lỗi khi gửi yêu cầu.', true);
                }
            } catch (err) {
                console.error('Lỗi mạng hoặc kết nối server:', err);
                if (forgotMessage) displayMessage(forgotMessage, 'Không thể kết nối đến máy chủ. Vui lòng thử lại sau.', true);
            }
        });
    }

});