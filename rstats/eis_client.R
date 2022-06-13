library(here)     # for file directory locations
library(dplyr)    # for pipe operations
library(jsonlite) # for JSON manipulations
library(httr)     # for web functions

# define our Oauth Client, note that secret is not truly secret
eis_app <- function() {
  oauth_app("eis", key = <provided_client_id>,
            secret = <provided_client_secret>)
}

# define the endpoints for EIS
eis_auth_endpoints <- function() {
  oauth_endpoint(
    authorize = "https://auth.cyentia.com/authorize?audience=https://eis-api.cyentia.com",
    access = "https://auth.cyentia.com/oauth/token")
}

# Fetch an Oauth access token, with caching
eis_api_token <- function() {
  oauth2.0_token(
    endpoint = eis_auth_endpoints(),
    app = eis_app(),
    config_init = httr::user_agent("httr"),
    query_authorize_extra = list(audience = "https://eis-api.cyentia.com"),
    scope = "openid profile email offline_access read:enhanced",
    cache = here::here(".eis-oauth")
    #use_oob = TRUE,
  )
}

# Helper function for making requests to the EIS API
eis_req <- function(path) {
  base_url <- "https://api.eis.cyentia.com/"
  req <- modify_url(base_url, path = path)
  resp <- GET(req,  config(token = eis_api_token()))
  stop_for_status(resp)
}

# CVEs (list)
resp <- eis_req("/v1/cve/list/2010")
resp_content <- content(resp)

# CVEs (search)
resp <- eis_req("/v1/cve/CVE-2020-5903")
resp_content <- content(resp, as = "text")
resp_content #%>% jsonlite::fromJSON(flatten = FALSE)

# Export
resp <- eis_req("/v1/export/20210910")
content(resp) %>% jsonlite::toJSON(pretty = TRUE, auto_unbox = TRUE)

