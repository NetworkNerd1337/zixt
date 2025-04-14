document.addEventListener('DOMContentLoaded', () => {
    const socket = io(baseUrl);

    socket.on('connect', () => {
        console.log('Connected to SocketIO server');
    });

    if (threadId) {
        socket.on('new_message', (data) => {
            if (data.thread_id === threadId) {
                const messagesDiv = document.getElementById('messages');
                const messageDiv = document.createElement('div');
                messageDiv.className = 'message';
                messageDiv.innerHTML = `<strong>${data.sender_id === {{ session['user_id'] }} ? 'You' : 'Them'}:</strong> ${data.message}`;
                if (data.file) {
                    if (data.file.match(/\.(png|jpg|jpeg|gif)$/)) {
                        messageDiv.innerHTML += `<img src="/static/uploads/${data.file}" alt="Attachment" style="max-width: 200px;">`;
                    } else {
                        messageDiv.innerHTML += `<a href="/static/uploads/${data.file}" target="_blank">${data.file}</a>`;
                    }
                }
                messagesDiv.appendChild(messageDiv);
                messagesDiv.scrollTop = messagesDiv.scrollHeight;
            }
        });
    }
});