#include "http_client.hpp"

#include <curl/curl.h>

http_client::http_client() : curl(curl_easy_init()) {
  if (curl == nullptr) {
    throw std::runtime_error("Failed to initialize libcurl");
  }
}

http_client::~http_client() {
  if (curl != nullptr) {
    curl_easy_cleanup(curl);
  }
}

std::size_t http_client::write_callback(char* contents, std::size_t size, std::size_t nmemb, std::stringstream* userp) {
  size_t total_size = size * nmemb;
  *userp << std::string(contents, total_size);
  return total_size;
}

picojson::value http_client::get_json(const std::string& url) {
  std::stringstream response_data;

  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

  CURLcode res = curl_easy_perform(curl);

  if (res != CURLE_OK) {
    throw std::runtime_error("HTTP request failed: " + std::string(curl_easy_strerror(res)));
  }

  long response_code = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

  static constexpr auto http_ok = 200;
  if (response_code != http_ok) {
    throw std::runtime_error("HTTP request returned status code: " + std::to_string(response_code));
  }

  picojson::value json_result;
  std::string parse_error = picojson::parse(json_result, response_data.str());

  if (!parse_error.empty()) {
    throw std::runtime_error("JSON parsing failed: " + parse_error);
  }

  return json_result;
}
