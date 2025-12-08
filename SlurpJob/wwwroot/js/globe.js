window.slurpGlobe = {
    instance: null,
    init: function (elementId) {
        const element = document.getElementById(elementId);
        if (!element) return;

        // Ensure Globe is loaded
        if (typeof Globe === 'undefined') {
            console.error("Globe.gl library not loaded");
            return;
        }

        this.instance = Globe()
            .globeImageUrl('//unpkg.com/three-globe/example/img/earth-night.jpg')
            .backgroundColor('#000000')
            .arcColor('color')
            .arcDashLength(0.4)
            .arcDashGap(2)
            .arcDashAnimateTime(2000)
            .pointColor(() => '#ff0000')
            .pointAltitude(0)
            .pointRadius(0.5)
            (element);

        this.instance.controls().autoRotate = true;
        this.instance.controls().autoRotateSpeed = 0.6;
    },
    updateArcs: function (arcs) {
        if (this.instance) {
            this.instance.arcsData(arcs);
        }
    }
};
