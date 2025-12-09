window.slurpTimeline = {
    charts: {},

    init: async function (canvasId, dotNetRef) {
        const ctx = document.getElementById(canvasId);
        if (!ctx) {
            console.error('Timeline canvas not found:', canvasId);
            return;
        }

        // Get initial data from Blazor
        const chartData = await dotNetRef.invokeMethodAsync('GetChartData');

        this.charts[canvasId] = new Chart(ctx, {
            type: 'bar',
            data: chartData,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        stacked: true,
                        ticks: { color: '#adb5bd' },
                        grid: { color: '#495057' }
                    },
                    y: {
                        stacked: true,
                        beginAtZero: true,
                        ticks: { color: '#adb5bd' },
                        grid: { color: '#495057' }
                    }
                },
                plugins: {
                    legend: {
                        labels: { color: '#adb5bd' }
                    }
                }
            }
        });

        // Store dotNetRef for updates
        this.charts[canvasId].dotNetRef = dotNetRef;
    },

    update: async function (canvasId) {
        const chart = this.charts[canvasId];
        if (!chart || !chart.dotNetRef) return;

        try {
            const newData = await chart.dotNetRef.invokeMethodAsync('GetChartData');
            chart.data = newData;
            chart.update('none'); // Update without animation for performance
        } catch (e) {
            console.error('Timeline update error:', e);
        }
    }
};
