# Traefik API Manager plugin

Traefik plugin to automatically call API Manager to replace requests headers.

## Description

The aim of this plugin is to update requests authorization header on the fly by calling an API Manager before.

When the plugin call the API Manager, it will retrieve a new token and update the `Authorization` request header with the new token. The original authorization header will be saved in a new header named `X-Forwarded-Authorization`.

## Installation

To install the plugin, you must add the plugin to your traefik configuration file :

```yaml
experimental:
  plugins:
    bouncer:
      moduleName: github.com/MGDIS/traefik-apimanager-plugin
      version: vX.Y.Z # To update
```

Then go to your docker compose file and add the following line to the traefik `command` line :

```yaml
- "--experimental.localPlugins.apimanagerplugin.moduleName=github.com/MGDIS/traefik-apimanager-plugin"
```

More details on [Traefik plugin installation documentation page](https://plugins.traefik.io/install).

## Configuration

The Traefik api manager plugin needs some values to configure API manager calls.

To set them, you must add some docker compose labels on the containers that will use the plugin :

### Authentication mode

You must declare which authentication mode you will use in the plugin.

The plugin supports OAuth 2.0 and API key modes.

```yaml
- "traefik.http.middlewares.apimanager.plugin.apimanagerplugin.authMode=apikey" # or authMode=oauth2
```

### API Key mode

The API Key mode only needs the information of the HTTP header (key and value) to add the header on each valid request.

```yaml
- "traefik.http.middlewares.apimanager.plugin.apimanagerplugin.headerName=X-Api-Key"
- "traefik.http.middlewares.apimanager.plugin.apimanagerplugin.headerValue=qwdkjasldoq0123qojwdoqiu12903"
```

### OAuth 2.0

Le mode OAuth 2.0 needs auth informations to retrieve tokens via the API Manager.

The following informations are needed :
- apiManagerURL : api manager auth url
- clientID : app public identifier
- clientSecret : app secret
- username : service account
- password : service account password
- scope : scopes you request access (optional and separated by spaces or commas)

```yaml
# oauth2
- "traefik.http.middlewares.apimanager.plugin.apimanagerplugin.apiManagerURL=http://apimanager:8080/auth"
- "traefik.http.middlewares.apimanager.plugin.apimanagerplugin.clientID=clientID"
- "traefik.http.middlewares.apimanager.plugin.apimanagerplugin.clientSecret=clientSecret"
- "traefik.http.middlewares.apimanager.plugin.apimanagerplugin.username=username"
- "traefik.http.middlewares.apimanager.plugin.apimanagerplugin.password=password"
- "traefik.http.middlewares.apimanager.plugin.apimanagerplugin.grantType=password"
- "traefik.http.middlewares.apimanager.plugin.apimanagerplugin.scope=example"
```

### Path restriction

This plugin can be restricted on a defined list of path of your containers. 

To use the path restriction mode, you need to set the `paths` variable with a regex paths array :

```yaml
- "traefik.http.middlewares.apimanager.plugin.apimanagerplugin.paths=^/demo$,^/demo/.+$,^/foobar/.*$"
```

By default, the middleware will send all requests to the api manager to update the Authorization header (or set the API key header in apikey mode).

### Middleware declaration

Do not forget to declare the middleware plugin on your containers like this :

```yaml
- "traefik.http.routers.app.middlewares=apimanager"
```

## Example

The `example` folder contains a docker compose file with a traefik configuration and a simple web server to test the plugin.

The example app is a simple web server that returns a JSON object that display received `Authorization` and `X-Forwarded-Authorization` headers.

Here the following Path restriction configuration :

```yaml
- "traefik.http.middlewares.apimanager.plugin.apimanagerplugin.paths=^/demo$,^/demo/.+$,^/foobar/.*$"
```

**Example with an ignored path:**

```sh
curl -s http://localhost/foobar | jq
```

Response :
```json
{
  "message": "Hello world !",
  "headers": {}
}
```

**Example with a valid path:**

```sh
curl -s -H "Authorization: Bearer xxxxxxxxx" http://localhost/demo | jq
```

Response :
```json
{
  "message": "Hello world !",
  "headers": {
    "Authorization": "Bearer fejHKnq8r92u94puqy1rSkUNCWBXmL6k",
    "X-Forwarded-Authorization": "Bearer xxxxxxxxx"
  }
}
```