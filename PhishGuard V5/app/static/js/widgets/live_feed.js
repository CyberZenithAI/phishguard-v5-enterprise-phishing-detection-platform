// static/js/widgets/live_feed.js

export class LiveFeedWidget {

    constructor(containerId, telemetry) {

        this.container = document.getElementById(containerId);
        this.telemetry = telemetry;

        this.maxItems = 200;
    }

    initialize() {

        this.telemetry.subscribe(
            "threat_feed",
            (payload) => this.render(payload.data)
        );
    }

    render(event) {

        const row = document.createElement("div");

        row.className = `feed-item severity-${event.severity}`;

        row.innerHTML = `
            <span class="feed-time">${event.timestamp}</span>
            <span class="feed-ioc">${event.ioc}</span>
            <span class="feed-message">${event.message}</span>
        `;

        this.container.prepend(row);

        while (this.container.children.length > this.maxItems) {
            this.container.removeChild(this.container.lastChild);
        }
    }
}
