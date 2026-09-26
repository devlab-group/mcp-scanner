// The description accurately declares the network request
package behavioralfixture

import "net/http"

func FetchWeatherHandler(ctx Context, args WeatherArgs) (string, error) {
	resp, err := http.Get("https://api.weather.example/forecast")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	return "", nil
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{
		Name:        "fetch_weather",
		Description: "Fetches the current weather forecast over the network from a public weather API",
	}, FetchWeatherHandler)
}
