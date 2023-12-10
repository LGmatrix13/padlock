document.addEventListener("DOMContentLoaded", async () => {
  navigator.geolocation.getCurrentPosition(success, error);

  function success(position) {
    const latitude = position.coords.latitude;
    const longitude = position.coords.longitude;

    const latitudeInput = document.getElementById("latitude");
    latitudeInput.value = latitude;
    latitudeInput.readOnly = true;
    const longitudeInput = document.getElementById("longitude");
    longitudeInput.value = longitude;
    longitudeInput.readOnly = true;
  }

  function error() {
    console.log("Error getting user location");
  }
});
