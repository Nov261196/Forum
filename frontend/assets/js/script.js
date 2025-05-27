document.addEventListener('DOMContentLoaded', () => {
    // Lấy tham chiếu đến các form
    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');
    const forgotForm = document.getElementById('forgot-form');

    // Lấy tham chiếu đến các link chuyển đổi form
    const registerLink = document.getElementById('register-link'); // "Đăng ký" trong form login
    const forgotPasswordLink = document.getElementById('forgot-password-link'); // "Quên mật khẩu?" trong form login
    const loginLinkFromRegister = document.getElementById('login-link-from-register'); // "Đăng nhập" trong form register
    const loginLinkFromForgot = document.getElementById('login-link-from-forgot'); // "Đăng nhập tại đây" trong form forgot


    // Hàm để hiển thị một form và ẩn các form còn lại
    function showForm(formToShow) {
        // Ẩn tất cả các form
        loginForm.classList.remove('active-form');
        registerForm.classList.remove('active-form');
        forgotForm.classList.remove('active-form');

        // Hiển thị form được chỉ định
        formToShow.classList.add('active-form');
    }

    // Gắn sự kiện click cho các link chuyển đổi
    if (registerLink) {
        registerLink.addEventListener('click', (e) => {
            e.preventDefault(); // Ngăn hành vi mặc định của label nếu có
            showForm(registerForm);
        });
    }

    if (forgotPasswordLink) {
        forgotPasswordLink.addEventListener('click', (e) => {
            e.preventDefault();
            showForm(forgotForm);
        });
    }

    if (loginLinkFromRegister) {
        loginLinkFromRegister.addEventListener('click', (e) => {
            e.preventDefault();
            showForm(loginForm);
        });
    }

    if (loginLinkFromForgot) {
        loginLinkFromForgot.addEventListener('click', (e) => {
            e.preventDefault();
            showForm(loginForm);
        });
    }

    // -------------------------------------------------------------
    // Thêm các sự kiện xử lý form (Đăng nhập, Đăng ký, Quên mật khẩu)
    // Các phần này bạn có thể giữ nguyên hoặc điều chỉnh tùy theo logic của bạn

    // Ví dụ về logic đăng nhập (bạn cần điền đầy đủ)
    const loginButton = document.getElementById('login-button');
    const loginEmailInput = document.getElementById('login-email');
    const loginPasswordInput = document.getElementById('login-password');
    const loginMessage = document.getElementById('login-message');

    if (loginButton) {
        loginButton.addEventListener('click', async () => {
            const email = loginEmailInput.value;
            const password = loginPasswordInput.value;

            loginMessage.textContent = ''; // Xóa thông báo cũ

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
                    loginMessage.textContent = data.message;
                    loginMessage.style.color = 'green';
                    // Lưu token vào localStorage hoặc sessionStorage
                    localStorage.setItem('token', data.token);
                    // Chuyển hướng người dùng hoặc cập nhật UI
                    window.location.href = '/dashboard.html'; // Ví dụ
                } else {
                    loginMessage.textContent = data.message || 'Đăng nhập thất bại.';
                    loginMessage.style.color = 'red';
                }
            } catch (error) {
                console.error('Lỗi đăng nhập:', error);
                loginMessage.textContent = 'Đã xảy ra lỗi mạng hoặc máy chủ không phản hồi.';
                loginMessage.style.color = 'red';
            }
        });
    }

    // Ví dụ về logic đăng ký (bạn cần điền đầy đủ)
    const registerButton = document.getElementById('register-button');
    const regFirstNameInput = document.getElementById('reg-first-name');
    const regLastNameInput = document.getElementById('reg-last-name');
    const regEmailInput = document.getElementById('reg-email');
    const regPasswordInput = document.getElementById('reg-password');
    const regConfirmPasswordInput = document.getElementById('reg-confirm-password');
    const regPhoneNumberInput = document.getElementById('reg-phone-number');
    const registerMessage = document.getElementById('register-message');

    if (registerButton) {
        registerButton.addEventListener('click', async () => {
            const username = `${regFirstNameInput.value} ${regLastNameInput.value}`.trim(); // Giả định username là First + Last name
            const email = regEmailInput.value;
            const password = regPasswordInput.value;
            const confirmPassword = regConfirmPasswordInput.value;
            // const phoneNumber = regPhoneNumberInput.value; // Nếu bạn muốn gửi cả số điện thoại

            registerMessage.textContent = ''; // Xóa thông báo cũ

            if (password !== confirmPassword) {
                registerMessage.textContent = 'Mật khẩu và xác nhận mật khẩu không khớp.';
                registerMessage.style.color = 'red';
                return;
            }
            if (password.length < 6) { // Ví dụ: yêu cầu mật khẩu ít nhất 6 ký tự
                registerMessage.textContent = 'Mật khẩu phải có ít nhất 6 ký tự.';
                registerMessage.style.color = 'red';
                return;
            }

            try {
                const response = await fetch('http://localhost:3000/api/register', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ username, email, password }), // Chỉ gửi những gì backend mong đợi
                });

                const data = await response.json();

                if (response.ok) {
                    registerMessage.textContent = data.message;
                    registerMessage.style.color = 'green';
                    // Tùy chọn: Chuyển hướng người dùng về form đăng nhập sau khi đăng ký thành công
                    setTimeout(() => {
                        showForm(loginForm);
                        // Xóa các trường input sau khi đăng ký thành công nếu muốn
                        regFirstNameInput.value = '';
                        regLastNameInput.value = '';
                        regEmailInput.value = '';
                        regPasswordInput.value = '';
                        regConfirmPasswordInput.value = '';
                        regPhoneNumberInput.value = '';
                    }, 2000);
                } else {
                    registerMessage.textContent = data.message || 'Đăng ký thất bại.';
                    registerMessage.style.color = 'red';
                }
            } catch (error) {
                console.error('Lỗi đăng ký:', error);
                registerMessage.textContent = 'Đã xảy ra lỗi mạng hoặc máy chủ không phản hồi.';
                registerMessage.style.color = 'red';
            }
        });
    }

    // Ví dụ về logic quên mật khẩu (bạn cần điền đầy đủ)
    const resetPasswordButton = document.getElementById('reset-password-button');
    const forgotEmailInput = document.getElementById('forgot-email');
    const forgotMessage = document.getElementById('forgot-message');

    if (resetPasswordButton) {
        resetPasswordButton.addEventListener('click', async () => {
            const email = forgotEmailInput.value;

            forgotMessage.textContent = ''; // Xóa thông báo cũ

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
                    forgotMessage.textContent = data.message; // Backend nên trả về thông báo chung chung
                    forgotMessage.style.color = 'green';
                    // Tùy chọn: Xóa trường email sau khi gửi yêu cầu
                    forgotEmailInput.value = '';
                } else {
                    // Mặc dù backend đã xử lý thông báo chung chung, nhưng nếu có lỗi khác
                    forgotMessage.textContent = data.message || 'Có lỗi xảy ra khi yêu cầu đặt lại mật khẩu.';
                    forgotMessage.style.color = 'red';
                }
            } catch (error) {
                console.error('Lỗi yêu cầu quên mật khẩu:', error);
                forgotMessage.textContent = 'Đã xảy ra lỗi mạng hoặc máy chủ không phản hồi.';
                forgotMessage.style.color = 'red';
            }
        });
    }
});