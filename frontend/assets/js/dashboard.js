document.addEventListener('DOMContentLoaded', async () => {
    const usernameDisplay = document.getElementById('username-display');
    const welcomeUsername = document.getElementById('welcome-username'); // Giữ lại cho trang dashboard
    const userAvatar = document.getElementById('user-avatar');
    const logoutButton = document.getElementById('logout-button');
    const userInfoDiv = document.getElementById('user-info');

    const token = localStorage.getItem('token');

    if (!token) {
        window.location.href = '/index.html';
        return;
    }

    async function fetchUserProfile() {
        try {
            const response = await fetch('http://localhost:3000/api/profile', {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                }
            });

            if (response.ok) {
                const userData = await response.json();
                if (usernameDisplay) {
                    usernameDisplay.textContent = userData.username || userData.email;
                }
                if (welcomeUsername) { // Cập nhật tên người dùng trên trang dashboard chính
                    welcomeUsername.textContent = userData.username || userData.email;
                }
                if (userAvatar && userData.avatar_url) {
                    userAvatar.src = userData.avatar_url;
                }
            } else if (response.status === 401) {
                alert('Phiên làm việc của bạn đã hết hạn. Vui lòng đăng nhập lại.');
                localStorage.removeItem('token');
                window.location.href = '/index.html';
            } else {
                const errorData = await response.json();
                console.error('Lỗi khi tải thông tin người dùng:', errorData.message);
                alert('Không thể tải thông tin người dùng. Vui lòng thử lại.');
            }
        } catch (error) {
            console.error('Lỗi mạng khi tải thông tin người dùng:', error);
            alert('Lỗi kết nối máy chủ. Không thể tải thông tin người dùng.');
        }
    }

    if (logoutButton) {
        logoutButton.addEventListener('click', (e) => {
            e.preventDefault();
            localStorage.removeItem('token');
            alert('Bạn đã đăng xuất thành công.');
            window.location.href = '/index.html';
        });
    }

    if (userInfoDiv) {
        userInfoDiv.addEventListener('click', (e) => {
            const dropdown = userInfoDiv.querySelector('.dropdown-menu');
            if (e.target.id === 'logout-button') return;

            if (dropdown.style.display === 'flex') {
                dropdown.style.display = 'none';
                dropdown.style.opacity = '0';
                dropdown.style.transform = 'translateY(-10px)';
            } else {
                dropdown.style.display = 'flex';
                setTimeout(() => {
                    dropdown.style.opacity = '1';
                    dropdown.style.transform = 'translateY(0)';
                }, 10);
            }
        });
        document.addEventListener('click', (e) => {
            if (userInfoDiv && !userInfoDiv.contains(e.target)) {
                const dropdown = userInfoDiv.querySelector('.dropdown-menu');
                if (dropdown) {
                    dropdown.style.display = 'none';
                    dropdown.style.opacity = '0';
                    dropdown.style.transform = 'translateY(-10px)';
                }
            }
        });
    }

    // XÓA TOÀN BỘ LOGIC UPLOAD AVATAR TỪ ĐÂY TRỞ XUỐNG
    // (Đoạn code bắt đầu từ 'const avatarUploadForm = document.getElementById('avatar-upload-form');'
    // và sự kiện 'avatarUploadForm.addEventListener('submit', ...)'

    fetchUserProfile();
});