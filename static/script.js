document.addEventListener('DOMContentLoaded', () => {
    const socket = io();
    const messageForm = document.getElementById('message-form');
    const messagesDiv = document.getElementById('messages');
    const threadList = document.querySelector('.thread-list ul');

    if (messageForm) {
        messageForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const formData = new FormData(messageForm);
            socket.emit('send_message', {
                thread_id: formData.get('thread_id'),
                content: formData.get('content')
            });
            messageForm.reset();
        });
    }

    socket.on('new_message', (data) => {
        if (data.thread_id == messageForm?.querySelector('input[name="thread_id"]').value) {
            const messageDiv = document.createElement('div');
            messageDiv.className = 'message';
            let content = `<p><strong>${data.sender} (${data.timestamp}):</strong> ${data.content}</p>`;
            if (data.file_name) {
                if (['image/png', 'image/jpeg', 'image/gif', 'image/bmp'].includes(data.file_type)) {
                    content += `<img src="/download/${data.file_path}" alt="${data.file_name}" style="max-width: 200px;">`;
                } else {
                    content += `<a href="/download/${data.file_path}">${data.file_name}</a>`;
                }
            }
            messageDiv.innerHTML = content;
            messagesDiv.appendChild(messageDiv);
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
        }
    });

    socket.on('thread_update', (data) => {
        if (data.deleted) {
            const threadItem = document.querySelector(`a[href="/thread/${data.thread_id}"]`)?.parentElement;
            if (threadItem) threadItem.remove();
        } else {
            const li = document.createElement('li');
            li.innerHTML = `<a href="/thread/${data.thread_id}">${data.name}</a>
                           <form method="POST" action="/delete_thread/${data.thread_id}" style="display:inline;">
                               <input type="hidden" name="_csrf_token" value="${document.querySelector('meta[name="csrf_token"]')?.content}">
                               <button type="submit" onclick="return confirm('Delete this thread?')">Delete</button>
                           </form>`;
            threadList.appendChild(li);
        }
    });

    socket.on('message_error', (data) => {
        alert(data.error);
    });
});