# Minimal transport confined to loopback inside the owned Redmine container.
require "net/http"
require "json"

begin
  input = JSON.parse(STDIN.read(16000))
  path = input.fetch("path")
  method = input.fetch("method")
  permit = case method
  when "GET"
    path.match?(%r{\A/(login|projects/p010-synthetic\.json|enumerations/issue_priorities\.json|issues/\d+\.json|issues\.json\?project_id=\d+&status_id=%2A&limit=100&offset=\d+)\z})
  when "POST"
    path == "/issues.json"
  when "PUT"
    path.match?(%r{\A/issues/\d+\.json\z})
  else
    false
  end
  raise "path refused" unless permit
  auth = input.fetch("auth")
  raise "authentication binding refused" unless ["sync", "reader", "none"].include?(auth)
  verb = {"GET" => Net::HTTP::Get, "POST" => Net::HTTP::Post, "PUT" => Net::HTTP::Put}.fetch(method)
  http = Net::HTTP.new("127.0.0.1", 3000, nil)
  http.open_timeout = 4
  http.read_timeout = 8
  request = verb.new(path, {"Accept" => path == "/login" ? "text/html" : "application/json"})
  if auth != "none"
    request["X-Redmine-API-Key"] = File.read("/usr/src/redmine/.p010-#{auth}-token", 160)
  end
  if input["body"]
    request["Content-Type"] = "application/json"
    request.body = JSON.generate(input["body"])
  end
  status = 0
  payload = ""
  http.request(request) do |response|
    status = response.code.to_i
    if status == 200 || status == 201
      response.read_body do |chunk|
        raise "response too large" if payload.bytesize + chunk.bytesize > 750_000
        payload << chunk
      end
    end
  end
  body = (path == "/login" || payload.empty?) ? nil : JSON.parse(payload)
  STDOUT.write(JSON.generate({"status" => status, "body" => body}))
rescue StandardError
  STDOUT.write(JSON.generate({"status" => 503, "body" => nil}))
end
