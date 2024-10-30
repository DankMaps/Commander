// File: static/js/scripts.js

document.addEventListener('DOMContentLoaded', function() {
    // Function to copy text to clipboard
    function copyToClipboard(text) {
        // Create a temporary textarea element
        const textarea = document.createElement('textarea');
        textarea.value = text;
        document.body.appendChild(textarea);
        textarea.select();
        try {
            document.execCommand('copy');
            return true;
        } catch (err) {
            console.error('Failed to copy text: ', err);
            return false;
        } finally {
            document.body.removeChild(textarea);
        }
    }

    // Add click event listeners to all copy buttons
    const copyButtons = document.querySelectorAll('.copy-btn');
    copyButtons.forEach(function(button) {
        button.addEventListener('click', function() {
            const command = this.getAttribute('data-clipboard-text');
            const success = copyToClipboard(command);
            if (success) {
                // Change button text to indicate success
                const originalText = this.textContent;
                this.textContent = 'Copied!';
                this.classList.remove('btn-outline-primary');
                this.classList.add('btn-success');
                // Revert back after 2 seconds
                setTimeout(() => {
                    this.textContent = originalText;
                    this.classList.remove('btn-success');
                    this.classList.add('btn-outline-primary');
                }, 2000);
            } else {
                alert('Failed to copy the command.');
            }
        });
    });
});
