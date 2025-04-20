document.addEventListener('DOMContentLoaded', () => {
    const socket = io();
    const messageForm = document.getElementById('message-form');
    const loginForm = document.getElementById('login-form');
    const messagesDiv = document.getElementById('messages');
    const threadList = document.querySelector('.thread-list ul');

    // Placeholder for session data (in practice, fetch securely)
    const session = {
        user_id: window.sessionUserId, // Assume injected by server
        secret: window.sessionSecret,   // Assume private key or secret
        public_key_hash: window.sessionPublicKeyHash
    };

    // Load Bulletproofs WASM (simplified, assumes bulletproofs.wasm)
    async function loadBulletproofsWasm() {
        const wasmModule = await fetch('/static/bulletproofs.wasm');
        const wasmBuffer = await wasmModule.arrayBuffer();
        return WebAssembly.instantiate(wasmBuffer, {});
    }

    async function generateAuthProof(userId, publicKeyHash, secret) {
        const wasm = await loadBulletproofsWasm();
        const proof = wasm.instance.exports.generate_auth_proof(userId, publicKeyHash, secret);
        const publicInputs = { public_key_hash: publicKeyHash };
        return { proof: btoa(String.fromCharCode(...new Uint8Array(proof))), publicInputs };
    }

    async function generateMessageProof(threadId, userId, timestamp, secret) {
        const wasm = await loadBulletproofsWasm();
        const proof = wasm.instance.exports.generate_message_proof(threadId, userId, timestamp, secret);
        const publicInputs = { thread_id: threadId };
        return { proof: btoa(String.fromCharCode(...new Uint8Array(proof))), publicInputs };
    }

    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(loginForm);
            const publicKeyHash = formData.get('public_key_hash');
            const privateKey = formData.get('private_key');
            const userId = session.user_id;

            try {
                const { proof, publicInputs } = await generateAuthProof(userId, publicKeyHash, privateKey);
                formData.set('bulletproof', JSON.stringify({ proof, publicInputs }));
                const response = await fetch('/login', {
                    method: 'POST',
                    body: formData
                });
                if (response.ok) {
                    window.location.href = '/dashboard';
                } else {
                    alert('Login failed');
                }
            } catch (error) {
                console.error('Proof generation failed:', error);
                alert('Proof generation failed');
            }
        });
    }

    if (messageForm) {
        messageForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(messageForm);
            const threadId = formData.get('thread_id');
            const content = formData.get('content');
            const userId = session.user_id;
            const timestamp = Math.floor(Date.now() / 1000);
            const secret = session.secret;

            try {
                const { proof, publicInputs } = await generateMessageProof(threadId, userId, timestamp, secret);
                socket.emit('send_message', {
                    thread_id: threadId,
                    content: content,
                    bulletproof: JSON.stringify({ proof, publicInputs })
                });
                messageForm.reset();
            } catch (error) {
                console.error('Proof generation failed:', error);
                alert('Proof generation failed');
            }
        });
    }

    socket.on('new_message', (data) => {
        if (data.thread_id == messageForm?.querySelector('input[name="thread_id"]').value) {
            const messageDiv = document.createElement('div');
            messageDiv.className = 'message';
            let content = `<p>${data.content}</p>`;
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
