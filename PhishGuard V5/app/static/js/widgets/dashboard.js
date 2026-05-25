// static/js/dashboard.js

import { LiveFeedWidget } from "./widgets/live_feed.js";
import { IOCTableWidget } from "./widgets/ioc_table.js";
import { RiskScoreWidget } from "./widgets/risk_score.js";
import { WorkerStatusWidget } from "./widgets/worker_status.js";
import { TelemetryManager } from "./widgets/telemetry.js";
import { ChartsManager } from "./widgets/charts.js";

class Dashboard {

    constructor() {

        this.telemetry = new TelemetryManager();

        this.liveFeed = new LiveFeedWidget(
            "liveThreatFeed",
            this.telemetry
        );

        this.iocTable = new IOCTableWidget(
            "iocTableBody",
            this.telemetry
        );

        this.riskWidget = new RiskScoreWidget(
            "riskGauge",
            this.telemetry
        );

        this.workerWidget = new WorkerStatusWidget(
            "workerStatus",
            this.telemetry
        );

        this.charts = new ChartsManager(this.telemetry);

        this.initialize();
    }

    async initialize() {

        try {

            await this.telemetry.connect();

            this.liveFeed.initialize();
            this.iocTable.initialize();
            this.riskWidget.initialize();
            this.workerWidget.initialize();
            this.charts.initialize();

        } catch (error) {

            console.error(error);

        }
    }
}

window.addEventListener(
    "DOMContentLoaded",
    () => new Dashboard(),
    { passive: true }
);
