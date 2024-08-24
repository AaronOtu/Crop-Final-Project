const city = document.querySelector(".location");
const date = document.querySelector(".date");
const weather_image = document.querySelector(".weather-img");
const temperature = document.querySelector(".temp");
const wind = document.querySelector(".wind");
const pressure = document.querySelector(".pressure");
const humidity = document.querySelector(".humidity");
const weather_state = document.querySelector(".weather-state");

// Geolocation API
if (navigator.geolocation) {
  navigator.geolocation.getCurrentPosition(success, error);
} else {
  alert("Geolocation feature not supported");
}

async function success(position) {
  const lat = position.coords.latitude;
  const long = position.coords.longitude;
  console.log(lat, long);
  let apiUrl = `http://api.openweathermap.org/data/2.5/weather?lat=${lat}&lon=${long}&APPID=3af25885126dbc4791bba802e680a5c3`;
  const response = await fetch(apiUrl);
  let data = await response.json();
  console.log(data);

  city.innerHTML = data.name;

  // Format the date to exclude the time
  const currentDate = formatDate(new Date());
  date.innerHTML = currentDate;

  // Convert temperature from Kelvin to Celsius and add unit
  temperature.innerHTML = `${Math.round(data.main.temp - 273.15)}°C`;

  // Add units to wind speed, pressure, and humidity
  wind.innerHTML = `${data.wind.speed} m/s`;
  pressure.innerHTML = `${data.main.pressure} hPa`;
  humidity.innerHTML = `${data.main.humidity}%`;
  weather_state.innerHTML = data.weather[0].description;

  // Changes with the weather logic
  switch (data.weather[0].main) {
    case "Rain":
      weather_image.src = 'static/images/rain.png';
      break;
    case "Clear":
      weather_image.src = 'static/images/clear.png';
      break;
    case "Mist":
      weather_image.src = 'static/images/mist.png';
      break;
    case "Clouds":
      weather_image.src = 'static/images/clouds.png';
      break;
    default:
      weather_image.src = 'static/images/drizzle.png';
  }
}

function error(error) {
  alert("Geolocation feature not supported");
}

function formatDate(date) {
  const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
  const months = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];

  const dayName = days[date.getDay()];
  const day = date.getDate();
  const month = months[date.getMonth()];
  const year = date.getFullYear();

  // Adding suffix for the day
  const daySuffix = (day) => {
    if (day > 3 && day < 21) return 'th';
    switch (day % 10) {
      case 1: return 'st';
      case 2: return 'nd';
      case 3: return 'rd';
      default: return 'th';
    }
  }

  return `${dayName}, ${day}${daySuffix(day)} ${month} ${year}`;
}
