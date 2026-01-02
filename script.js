// script.js - Simple functionality
async function encrypt() {
    const text = document.getElementById('encrypt-text').value;
    const key = document.getElementById('encrypt-key').value;
    
    if (!text || !key) {
        alert('Please enter both text and key');
        return;
    }
    
    try {
        const response = await fetch('/encrypt', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({text, key})
        });
        
        const data = await response.json();
        
        if (data.result) {
            document.getElementById('encrypt-result').textContent = data.result;
            document.getElementById('decrypt-text').value = data.result;
        } else {
            alert('Error: ' + data.error);
        }
    } catch (error) {
        alert('Failed to encrypt');
    }
}

async function decrypt() {
    const text = document.getElementById('decrypt-text').value;
    const key = document.getElementById('decrypt-key').value;
    
    if (!text || !key) {
        alert('Please enter both text and key');
        return;
    }
    
    try {
        const response = await fetch('/decrypt', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({text, key})
        });
        
        const data = await response.json();
        
        if (data.result) {
            document.getElementById('decrypt-result').textContent = data.result;
        } else {
            alert('Error: ' + data.error);
        }
    } catch (error) {
        alert('Failed to decrypt');
    }
}

// Auto-encrypt example on load
window.onload = function() {
    setTimeout(() => {
        if (document.getElementById('encrypt-text').value) {
            encrypt();
        }
    }, 500);
}