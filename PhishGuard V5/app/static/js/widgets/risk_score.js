// static/js/widgets/risk_score.js

export class RiskScoreWidget {

    constructor(containerId, telemetry) {

        this.telemetry = telemetry;

        this.chart = new ApexCharts(
            document.querySelector(`#${containerId}`),
            {
                chart: {
                    type: "radialBar",
                    height: 350
                },
                series: [0],
                labels: ["Risk Score"]
            }
        );
    }

    initialize() {

        this.chart.render();

        this.telemetry.subscribe(
            "risk_score",
            (payload) => this.update(payload.data)
        );
    }

    update(data) {

        this.chart.updateSeries([data.score]);
    }
}
