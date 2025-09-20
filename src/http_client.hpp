#pragma once

#include <picojson/picojson.h>

#include <sstream>
#include <string>

class http_client {
 public:
  http_client();
  ~http_client();

  http_client(const http_client&) = delete;
  http_client& operator=(const http_client&) = delete;

  http_client(http_client&&) = default;
  http_client& operator=(http_client&&) = default;

  picojson::value get_json(const std::string& url);

 private:
  void* curl;

  static std::size_t write_callback(char* contents, std::size_t size, std::size_t nmemb, std::stringstream* userp);
};
