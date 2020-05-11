function initViz() {
    var containerDiv = document.getElementById("vizContainer"),
    url = "https://public.tableau.com/views/enabler_organization/Dashboard1?:display_count=y&publish=yes&:origin=viz_share_link";

    var viz = new tableau.Viz(containerDiv, url);
}
