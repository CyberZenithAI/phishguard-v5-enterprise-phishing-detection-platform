// static/js/widgets/worker_status.js

export class WorkerStatusWidget {

    constructor(containerId, telemetry) {

        this.container = document.getElementById(containerId);
        this.telemetry = telemetry;
    }

    initialize() {

        this.telemetry.subscribe(
            "worker_status",
            (payload) => this.render(payload.data)
        );
    }

    render(data) {

        this.container.innerHTML = `
            <div class="metric">
                Active Workers: ${data.active_workers}
            </div>

            <div class="metric">
                Queue Depth: ${data.queue_depth}
            </div>

            <div class="metric">
                Throughput: ${data.throughput}
            </div>

            <div class="metric">
                Heartbeat: ${data.heartbeat}
            </div>
        `;
    }
}
