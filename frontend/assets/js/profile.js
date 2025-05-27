document.addEventListener('DOMContentLoaded', async () => {
    // --- Các phần tử Navbar (để hiển thị thông tin user trên Navbar) ---
    const usernameDisplay = document.getElementById('username-display');
    const userAvatar = document.getElementById('user-avatar');
    const logoutButton = document.getElementById('logout-button');
    const userInfoDiv = document.getElementById('user-info'); // Để xử lý dropdown

    // --- Các phần tử trang Profile ---
    const currentProfileAvatar = document.getElementById('current-profile-avatar');
    const profileUsername = document.getElementById('profile-username');
    const profileEmail = document.getElementById('profile-email');
    const profileCreatedAt = document.getElementById('profile-created-at');
    
    // Inputs và form upload ảnh
    const avatarUploadForm = document.getElementById('avatar-upload-form');
    const avatarInput = document.getElementById('avatar-input'); // Input file ẩn trong avatar-display-wrapper (icon camera)
    const avatarInputForm = document.getElementById('avatar-input-form'); // Input file ẩn trong form upload riêng (nút "Chọn ảnh")
    const fileNameDisplay = document.getElementById('file-name-display'); // Hiển thị tên file đã chọn
    const avatarUploadMessage = document.getElementById('avatar-upload-message'); // Thông báo upload

    const token = localStorage.getItem('token');

    // Chuyển hướng nếu không có token
    if (!token) {
        window.location.href = '/index.html';
        return;
    }

    // Hàm để lấy thông tin người dùng từ backend
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
                console.log('User data from API:', userData); // KIỂM TRA ĐIỀU NÀY
        console.log('Avatar URL from API:', userData.avatar_url); // RẤT QUAN TRỌNG ĐỂ KIỂM TRA
                
                // Cập nhật Navbar
                if (usernameDisplay) usernameDisplay.textContent = userData.username || userData.email;
                // Cập nhật ảnh avatar trên Navbar (nếu có avatar_url và phần tử tồn tại)
                if (userAvatar && userData.avatar_url) {
                    userAvatar.src = userData.avatar_url;
                } else if (userAvatar) {
                    // Đặt ảnh mặc định nếu không có avatar_url
                    userAvatar.src = '/assets/images/logo-icon.png'; // <--- SỬA THÀNH ĐƯỜNG DẪN TUYỆT ĐỐI NÀY
                }

                // Cập nhật thông tin trên trang Profile
                // Cập nhật ảnh avatar chính trên Profile (nếu có avatar_url và phần tử tồn tại)
                if (currentProfileAvatar && userData.avatar_url) {
                    currentProfileAvatar.src = userData.avatar_url;
                } else if (currentProfileAvatar) {
                    // Đặt ảnh mặc định nếu không có avatar_url
                    currentProfileAvatar.src = '/assets/images/logo-icon.png'; // <--- SỬA THÀNH ĐƯỜNG DẪN TUYỆT ĐỐI NÀY
                }

                if (profileUsername) profileUsername.textContent = userData.username || userData.email;
                if (profileEmail) profileEmail.textContent = userData.email;
                if (profileCreatedAt && userData.created_at) {
                    const dateOptions = { year: 'numeric', month: 'long', day: 'numeric' };
                    profileCreatedAt.textContent = new Date(userData.created_at).toLocaleDateString('vi-VN', dateOptions);
                }

            } else if (response.status === 401) {
                alert('Phiên làm việc của bạn đã hết hạn. Vui lòng đăng nhập lại.');
                localStorage.removeItem('token');
                window.location.href = '/index.html';
            } else {
                const errorData = await response.json();
                console.error('Lỗi khi lấy thông tin người dùng:', errorData.message);
                alert('Không thể tải thông tin người dùng. Vui lòng thử lại.');
            }
        } catch (error) {
            console.error('Lỗi mạng khi lấy thông tin người dùng:', error);
            alert('Lỗi kết nối máy chủ. Không thể tải thông tin người dùng.');
        }
    }

    // Xử lý nút đăng xuất
    if (logoutButton) {
        logoutButton.addEventListener('click', (e) => {
            e.preventDefault();
            localStorage.removeItem('token');
            alert('Bạn đã đăng xuất thành công.');
            window.location.href = '/index.html';
        });
    }

    // Xử lý hiển thị/ẩn dropdown menu trên Navbar
    if (userInfoDiv) {
        userInfoDiv.addEventListener('click', (e) => {
            const dropdown = userInfoDiv.querySelector('.dropdown-menu');
            // Ngăn không cho sự kiện click từ nút logout làm đóng dropdown
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
        // Đóng dropdown khi click ra ngoài
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

    // Xử lý chọn file từ input ẩn trong avatar-display-wrapper (icon camera)
    if (avatarInput) {
        avatarInput.addEventListener('change', () => {
            if (avatarInput.files.length > 0) {
                // Gán FileList từ avatarInput (icon camera) sang avatarInputForm (nút "Chọn ảnh")
                avatarInputForm.files = avatarInput.files;
                fileNameDisplay.textContent = avatarInput.files[0].name;
                avatarUploadMessage.textContent = 'Ảnh đã chọn. Nhấn "Tải lên" để cập nhật.';
                avatarUploadMessage.style.color = 'blue';
            } else {
                avatarInputForm.value = ''; // Reset input của form upload
                fileNameDisplay.textContent = 'Chưa có file nào được chọn';
                avatarUploadMessage.textContent = '';
            }
        });
    }

    // Xử lý hiển thị tên file khi chọn từ form upload riêng (nút "Chọn ảnh")
    if (avatarInputForm) {
        avatarInputForm.addEventListener('change', () => {
            if (avatarInputForm.files.length > 0) {
                fileNameDisplay.textContent = avatarInputForm.files[0].name;
                avatarUploadMessage.textContent = ''; // Xóa thông báo cũ
            } else {
                fileNameDisplay.textContent = 'Chưa có file nào được chọn';
            }
        });
    }

    // Xử lý upload avatar khi form được submit
    if (avatarUploadForm) {
        avatarUploadForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            // Luôn lấy file từ avatarInputForm, đảm bảo rằng file đã được chọn
            const file = avatarInputForm.files[0]; 
            if (!file) {
                avatarUploadMessage.textContent = 'Vui lòng chọn một file ảnh.';
                avatarUploadMessage.style.color = 'red';
                return;
            }

            const formData = new FormData();
            formData.append('avatar', file); // 'avatar' phải khớp với tên trường trong Multer (upload.single('avatar'))

            try {
                const response = await fetch('http://localhost:3000/api/upload-avatar', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`
                        // KHÔNG cần 'Content-Type': 'application/json' khi gửi FormData
                    },
                    body: formData, // FormData tự động đặt Content-Type là multipart/form-data
                });

                const data = await response.json();
                console.log('Upload response data:', data); // KIỂM TRA ĐIỀU NÀY
                console.log('Uploaded Avatar URL:', data.avatar_url); // RẤT QUAN TRỌNG

                if (response.ok) {
                    avatarUploadMessage.textContent = data.message;
                    avatarUploadMessage.style.color = 'green';
                    
                    // Cập nhật ngay ảnh trên Navbar và trên trang profile sau khi upload thành công
                    if (userAvatar && data.avatar_url) {
                        userAvatar.src = data.avatar_url;
                        currentProfileAvatar.src = data.avatar_url; 
                    }
                    
                    // Reset trạng thái input file và hiển thị
                    fileNameDisplay.textContent = 'Chưa có file nào được chọn';
                    avatarInputForm.value = ''; // Xóa file đã chọn trong input để có thể chọn lại cùng một file
                    // avatarInput.value = ''; // Nếu muốn reset cả input của icon camera
                } else {
                    avatarUploadMessage.textContent = data.message || 'Lỗi khi tải ảnh lên.';
                    avatarUploadMessage.style.color = 'red';
                }
            } catch (error) {
                console.error('Lỗi khi tải ảnh lên:', error);
                avatarUploadMessage.textContent = 'Lỗi mạng hoặc máy chủ không phản hồi khi tải ảnh lên.';
                avatarUploadMessage.style.color = 'red';
            }
        });
    }

    // Gọi hàm fetchUserProfile khi trang tải xong để hiển thị thông tin ban đầu
    fetchUserProfile();

    // Bạn có thể thêm xử lý cho nút "Chỉnh sửa hồ sơ" và "Đổi mật khẩu" ở đây
    const editProfileBtn = document.getElementById('edit-profile-btn');
    if (editProfileBtn) {
        editProfileBtn.addEventListener('click', () => {
            alert('Chức năng chỉnh sửa hồ sơ chưa được triển khai.');
        });
    }
    const changePasswordBtn = document.getElementById('change-password-btn');
    if (changePasswordBtn) {
        changePasswordBtn.addEventListener('click', () => {
            alert('Chức năng đổi mật khẩu chưa được triển khai.');
        });
    }
});