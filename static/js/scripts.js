function selectSpot(spotId) {
    const spots = document.querySelectorAll('.parking-spot');
    spots.forEach(spot => spot.classList.remove('selected'));
    const selectedSpot = document.querySelector(`[data-spot-id="${spotId}"]`);
    if (selectedSpot.classList.contains('available')) {
        selectedSpot.classList.add('selected');
        document.getElementById('spot_id').value = spotId;
        document.getElementById('bookButton').disabled = false;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('searchLots');
    if (searchInput) {
        searchInput.addEventListener('input', () => {
            const query = searchInput.value.toLowerCase();
            const lots = document.querySelectorAll('#lotList .list-group-item');
            lots.forEach(lot => {
                const text = lot.textContent.toLowerCase();
                lot.style.display = text.includes(query) ? '' : 'none';
            });
        });
    }
});