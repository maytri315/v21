document.addEventListener('DOMContentLoaded', function() {
    // --- Auto-hide flash messages (Bootstrap 4 fade out) ---
    // Ensure this script block runs only once to prevent duplicate event listeners or timeouts.
    if (window.myAppScriptsLoaded) {
        return; // Script already executed
    }
    window.myAppScriptsLoaded = true; // Set a flag to indicate the script has run

    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        // Add a data attribute to the alert to store the timeout ID.
        // This prevents multiple timeouts from being set if the script somehow runs again.
        if (!alert.dataset.autoDismissTimeoutId) {
            const timeoutId = setTimeout(() => {
                $(alert).alert('close'); // Use jQuery for Bootstrap's alert close functionality
                // Optional: Clean up the data attribute after closing if needed,
                // but Bootstrap usually removes the element from DOM anyway.
                delete alert.dataset.autoDismissTimeoutId; 
            }, 5000); // 5 seconds
            alert.dataset.autoDismissTimeoutId = timeoutId; // Store the timeout ID
        }
    });

    // --- Toggle spot status display in admin search (already present) ---
    const searchTypeSelect = document.getElementById('search_type');
    if (searchTypeSelect) {
        searchTypeSelect.addEventListener('change', function() {
            const spotStatusDiv = document.getElementById('spot_status');
            if (spotStatusDiv) {
                spotStatusDiv.style.display = this.value === 'spots' ? 'block' : 'none';
            }
        });
        // Initial check on page load for search form
        const spotStatusDiv = document.getElementById('spot_status');
        if (spotStatusDiv) {
             spotStatusDiv.style.display = searchTypeSelect.value === 'spots' ? 'block' : 'none';
        }
    }

    // --- Custom Confirmation Modal Logic ---
    let currentFormToSubmit = null; // Variable to store the form that needs confirmation

    // Attach click listener to all buttons that need confirmation
    document.querySelectorAll('[data-confirm]').forEach(button => {
        button.addEventListener('click', function(event) {
            event.preventDefault(); // Prevent immediate form submission
            currentFormToSubmit = this.closest('form'); // Get the parent form

            const message = this.getAttribute('data-confirm') || 'Are you sure you want to proceed?';
            document.getElementById('modalMessage').textContent = message;

            // Show the modal
            $('#confirmationModal').modal('show');
        });
    });

    // Handle the 'Confirm' button click inside the modal
    document.getElementById('confirmActionBtn').addEventListener('click', function() {
        if (currentFormToSubmit) {
            currentFormToSubmit.submit(); // Submit the stored form
            currentFormToSubmit = null; // Clear the stored form
        }
        $('#confirmationModal').modal('hide'); // Hide the modal
    });
});
