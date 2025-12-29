import { chromium, Route } from 'playwright';
import * as readline from 'readline';

// IPC Setup
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: false
});

let _page: any = null;
const pendingRequests = new Map<number, { route: Route, request: any }>();
let requestIdCounter = 0;

console.log(JSON.stringify({ event: "READY" }));

rl.on('line', async (line) => {
    try {
        const msg = JSON.parse(line);
        processCommand(msg);
    } catch (e) {
        // Ignore non-JSON lines or log error
    }
});

async function processCommand(cmd: any) {
    if (cmd.command === "NAVIGATE") {
        pendingRequests.clear();
        if (_page) {
            try {
                // Disable timeout
                await _page.goto(cmd.url, { timeout: 0, waitUntil: 'domcontentloaded' });
            } catch (e: any) {
                console.log(JSON.stringify({ event: "LOG", message: `Nav Error: ${e.message}` }));
            }
        } else {
            launchBrowser(cmd.url);
        }
    }

    if (cmd.command === "CONTINUE") {
        const { id, method, headers, body, interceptResponse } = cmd;
        const pending = pendingRequests.get(id);
        if (pending) {
            const overrides: any = { method, headers };
            if (body !== undefined) overrides.postData = body;

            if (interceptResponse) {
                // FETCH mode: Get response, send to GUI, wait again
                try {
                    // We must delete from pending map? No, we need it for fulfill() later.
                    // But we can't route.continue() AND route.fetch() on same route object?
                    // route.fetch() does NOT consume the route. It just makes a request.
                    // We still need to call fulfill() on the route object later.

                    const response = await pending.route.fetch(overrides);
                    let responseBody = "";
                    try {
                        responseBody = await response.text();
                    } catch (e) {
                        responseBody = "<binary/empty>";
                    }

                    console.log(JSON.stringify({
                        event: "RESPONSE_INTERCEPTED",
                        id: id,
                        status: response.status(),
                        headers: response.headers(),
                        body: responseBody
                    }));

                    // Keep 'pending' in the map! We will need it for FULFILL_RESPONSE.
                } catch (e: any) {
                    console.log(JSON.stringify({ event: "LOG", message: `Fetch Error: ${e.message}` }));
                    pending.route.abort();
                    pendingRequests.delete(id);
                }
            } else {
                // Normal mode
                try {
                    await pending.route.continue(overrides);
                } catch (e) { }
                pendingRequests.delete(id);
            }
        }
    }

    if (cmd.command === "FULFILL_RESPONSE") {
        const { id, status, headers, body } = cmd;
        const pending = pendingRequests.get(id);
        if (pending) {
            try {
                await pending.route.fulfill({
                    status: status,
                    headers: headers,
                    body: body
                });
            } catch (e) { }
            pendingRequests.delete(id);
        }
    }

    if (cmd.command === "SEND_REQUEST") {
        const { id, method, url, headers, body } = cmd;
        try {
            // Use page.request to share session context
            const response = await _page.request.fetch(url, {
                method: method,
                headers: headers,
                data: body
            });

            let responseBody = "";
            try { responseBody = await response.text(); } catch (e) {
                responseBody = `<binary/empty> (Status ${response.status()})`;
            }

            console.log(JSON.stringify({
                event: "REPEATER_RESPONSE",
                id: id,
                status: response.status(),
                headers: response.headers(),
                body: responseBody
            }));
        } catch (e: any) {
            console.log(JSON.stringify({ event: "LOG", message: `Repeater Error: ${e.message}` }));
        }
    }

    if (cmd.command === "DROP") {
        const { id } = cmd;
        const pending = pendingRequests.get(id);
        if (pending) {
            try { await pending.route.abort(); } catch (e) { }
            pendingRequests.delete(id);
        }
    }
}

async function launchBrowser(url: string) {
    const browser = await chromium.launch({ headless: false });
    const context = await browser.newContext();
    _page = await context.newPage();

    // Intercept all requests
    await _page.route('**', async (route: Route) => {
        const request = route.request();
        const url = request.url().toLowerCase();
        const resourceType = request.resourceType();

        // 1. FILTER STATIC ASSETS (Auto-continue to prevent noise & timeouts)
        // Common static types + extensions
        const ignoredTypes = ['image', 'stylesheet', 'font', 'media'];
        const ignoredExtensions = ['.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.woff2', '.ttf', '.ico'];

        // Check if it's a static resource or ends with static extension (unless it's an XHR/Fetch)
        if (ignoredTypes.includes(resourceType) || ignoredExtensions.some(ext => url.split('?')[0].endsWith(ext))) {
            await route.continue();
            return;
        }

        // Filter noise (favicon) - this was here before, keeping it for now, though the above filter might catch it.
        if (request.url().includes('favicon')) {
            await route.continue();
            return;
        }

        const id = ++requestIdCounter;
        pendingRequests.set(id, { route, request });

        // Send event to Rust
        console.log(JSON.stringify({
            event: "REQUEST_INTERCEPTED",
            id: id,
            method: request.method(),
            url: request.url(),
            headers: request.headers(),
            body: request.postData() || null
        }));
    });

    try {
        // Disable timeout (0) so it doesn't fail while waiting for user interaction
        await _page.goto(url, { timeout: 0, waitUntil: 'domcontentloaded' });
    } catch (e: any) {
        console.log(JSON.stringify({ event: "LOG", message: `Error loading page: ${e.message}` }));
    }
}
