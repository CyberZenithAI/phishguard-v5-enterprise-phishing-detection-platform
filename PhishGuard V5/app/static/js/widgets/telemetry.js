// static/js/widgets/telemetry.js

export class TelemetryManager {

    constructor() {

        this.socket = null;
        this.listeners = new Map();

        this.reconnectDelay = 5000;
        this.heartbeatInterval = null;
    }

    async connect() {

        return new Promise((resolve, reject) => {

            const protocol = location.protocol === "https:" ? "wss" : "ws";

            this.socket = new WebSocket(
                `${protocol}://${location.host}/ws/telemetry`
            );

            this.socket.onopen = () => {

                this.startHeartbeat();

                resolve();

            };

            this.socket.onerror = reject;

            this.socket.onclose = () => {

                clearInterval(this.heartbeatInterval);

                setTimeout(
                    () => this.connect(),
                    this.reconnectDelay
                );

            };

            this.socket.onmessage = (event) => {

                try {

                    const payload = JSON.parse(event.data);

                    this.dispatch(payload);

                } catch (_) {}

            };
        });
    }

    subscribe(event, callback) {

        if (!this.listeners.has(event)) {
            this.listeners.set(event, []);
        }

        this.listeners.get(event).push(callback);
    }

    dispatch(payload) {

        const listeners = this.listeners.get(payload.type) || [];

        for (const callback of listeners) {
            requestAnimationFrame(() => callback(payload));
        }
    }

    startHeartbeat() {

        this.heartbeatInterval = setInterval(() => {

            if (this.socket.readyState === WebSocket.OPEN) {

                this.socket.send(
                    JSON.stringify({
                        type: "heartbeat",
                        ts: Date.now()
                    })
                );
            }

        }, 30000);
    }
}
