document.getElementById('encrypt-form').addEventListener('submit', function(event) {
    event.preventDefault();
    const filePath = document.getElementById('encrypt-file-path').value;
    const key = document.getElementById('encrypt-key').value;

    // Call the backend encryption function
    fetch('/encrypt', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ file_path: filePath, key: key })
    })
    .then(response => response.json())
    .then(data => {
        alert(data.message);
        // Clear previous download links
        const existingLinks = document.querySelectorAll('.download-link');
        existingLinks.forEach(link => link.remove());

        // Provide download link for the encrypted file
        const downloadLink = document.createElement('a');
        downloadLink.href = filePath + '.enc';
        downloadLink.innerText = 'Download Encrypted File';
        downloadLink.className = 'download-link'; // Add class for easy removal
        downloadLink.style.display = 'block'; // Make it a block element
        document.body.appendChild(downloadLink);
    })
    .catch(error => {
        console.error('Error:', error);
    });
});

document.getElementById('decrypt-form').addEventListener('submit', function(event) {
    event.preventDefault();
    const encryptedFilePath = document.getElementById('decrypt-file-path').value;
    const key = document.getElementById('decrypt-key').value;

    // Call the backend decryption function
    fetch('/decrypt', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ encrypted_file_path: encryptedFilePath, key: key })
    })
    .then(response => response.json())
    .then(data => {
        alert(data.message);
        // Clear previous download links
        const existingLinks = document.querySelectorAll('.download-link');
        existingLinks.forEach(link => link.remove());

        // Provide download link for the decrypted file
        const downloadLink = document.createElement('a');
        downloadLink.href = encryptedFilePath.replace('.enc', '');
        downloadLink.innerText = 'Download Decrypted File';
        downloadLink.className = 'download-link'; // Add class for easy removal
        downloadLink.style.display = 'block'; // Make it a block element
        document.body.appendChild(downloadLink);
    })
    .catch(error => {
        console.error('Error:', error);
    });
});
