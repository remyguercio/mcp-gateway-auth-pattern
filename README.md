```
client$ uv run mcp-auth-client --debug http://localhost:8003/mcp
gateway$ uv run mcp-auth-gateway --auth-server-url https://your-idp.your-tailnet.ts.net/ --mcp-server-url http://localhost:8001 --debug
server$ uv run mcp-auth-server --auth-server-url https://your-idp.your-tailet.ts.net/ --debug
```


## Wildly Permissive ACL Capability Grant to use for testing.
```
{
	"src": ["*"],
	"dst": ["*"],
	"app": {
		"test-tailscale.com/idp/sts/openly-allow": [
			{
				"users":     ["*"],
				"resources": ["*"],
			},
		],
	},
},
```
