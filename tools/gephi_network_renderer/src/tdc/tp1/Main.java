package tdc.tp1;

import org.gephi.appearance.api.AppearanceController;
import org.gephi.appearance.api.AppearanceModel;
import org.gephi.appearance.api.Function;
import org.gephi.appearance.plugin.RankingLabelSizeTransformer;
import org.gephi.appearance.plugin.RankingNodeSizeTransformer;
import org.gephi.datalab.api.AttributeColumnsController;
import org.gephi.graph.api.*;
import org.gephi.io.exporter.api.ExportController;
import org.gephi.layout.plugin.fruchterman.FruchtermanReingold;
import org.gephi.preview.api.PreviewController;
import org.gephi.preview.api.PreviewModel;
import org.gephi.preview.api.PreviewProperty;
import org.gephi.preview.types.EdgeColor;
import org.gephi.project.api.ProjectController;
import org.openide.util.Lookup;

import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Paths;

public class Main {

    public static void main(String[] args) {
        String inputFile = args[0];
        String outputFile = args[1] + Paths.get(args[0]).getFileName().toString();
        String edgesInputFile = inputFile + "_edges.csv";
        String nodesInputFile = inputFile + "_nodes.csv";

        //Init a project - and therefore a workspace
        ProjectController pc = Lookup.getDefault().lookup(ProjectController.class);
        pc.newProject();

        //Get models and controllers for this new workspace - will be useful later
        GraphModel graphModel = Lookup.getDefault().lookup(GraphController.class).getGraphModel();
        PreviewModel model = Lookup.getDefault().lookup(PreviewController.class).getModel();
        AttributeColumnsController attributeColumnsController =
                Lookup.getDefault().lookup(AttributeColumnsController.class);
        AppearanceController appearanceController = Lookup.getDefault().lookup(AppearanceController.class);
        AppearanceModel appearanceModel = appearanceController.getModel();


        String[] edgesColumnNames = new String[3];
        edgesColumnNames[0] = "Source";
        edgesColumnNames[1] = "Target";
        edgesColumnNames[2] = "Type";

        Class[] edgesColumnTypes = new Class[3];
        edgesColumnTypes[0] = String.class;
        edgesColumnTypes[1] = String.class;
        edgesColumnTypes[2] = String.class;

        String[] nodesColumnNames = new String[3];
        nodesColumnNames[0] = "Id";
        nodesColumnNames[1] = "Label";
        nodesColumnNames[2] = "Weight";

        Class[] nodesColumnTypes = new Class[3];
        nodesColumnTypes[0] = String.class;
        nodesColumnTypes[1] = String.class;
        nodesColumnTypes[2] = Float.class;
        try {
            File nodesFile = new File(nodesInputFile);
            attributeColumnsController.importCSVToNodesTable(graphModel.getGraph(),
                    nodesFile, ';', Charset.defaultCharset(),
                    nodesColumnNames, nodesColumnTypes, false);

            File edgesFile = new File(edgesInputFile);
            attributeColumnsController.importCSVToEdgesTable(graphModel.getGraph(),
                    edgesFile, ';', Charset.defaultCharset(),
                    edgesColumnNames, edgesColumnTypes, false);
        } catch (Exception ex) {
            ex.printStackTrace();
            return;
        }

        UndirectedGraph graph = graphModel.getUndirectedGraph();

        // Rank node size by Weight
        Column nodeWeightColumn = graphModel.getNodeTable().getColumn(nodesColumnNames[2]);
        Function nodeWeightRanking = appearanceModel.getNodeFunction(graph,
                nodeWeightColumn, RankingNodeSizeTransformer.class);
        RankingNodeSizeTransformer nodeWeightTransformer = nodeWeightRanking.getTransformer();
        nodeWeightTransformer.setMinSize(10);
        nodeWeightTransformer.setMaxSize(50);
        appearanceController.transform(nodeWeightRanking);

        // Rank node label size by Weight
        Function nodeLabelRanking = appearanceModel.getNodeFunction(graph,
                nodeWeightColumn, RankingLabelSizeTransformer.class);
        RankingLabelSizeTransformer nodeLabelTransformer = nodeLabelRanking.getTransformer();
        nodeLabelTransformer.setMinSize(5);
        nodeLabelTransformer.setMaxSize(50);
        appearanceController.transform(nodeLabelRanking);

        // Apply layout
        FruchtermanReingold fruchtermanReingold = new FruchtermanReingold(null);
        fruchtermanReingold.resetPropertiesValues();
        fruchtermanReingold.setGraphModel(graphModel);
        fruchtermanReingold.setSpeed(1.0d);
        fruchtermanReingold.setArea(500.0f);
        fruchtermanReingold.setGravity(3.0d);

        fruchtermanReingold.initAlgo();

        int iterations = (int)Math.pow(graph.getNodeCount(), 2);

        for(int i = 0; i < iterations && fruchtermanReingold.canAlgo(); i++) {
            fruchtermanReingold.goAlgo();
        }
        fruchtermanReingold.endAlgo();

        for (Node n: graph.getNodes()) {
            n.setColor(Color.LIGHT_GRAY);
        }

        // Preview
        model.getProperties().putValue(PreviewProperty.SHOW_NODE_LABELS, Boolean.TRUE);
        model.getProperties().putValue(PreviewProperty.EDGE_COLOR, new EdgeColor(Color.LIGHT_GRAY));
        model.getProperties().putValue(PreviewProperty.EDGE_CURVED, Boolean.FALSE);
        model.getProperties().putValue(PreviewProperty.EDGE_THICKNESS, new Float(0.1f));

        // Export
        ExportController ec = Lookup.getDefault().lookup(ExportController.class);
        try {
            ec.exportFile(new File(outputFile + ".pdf"));
        } catch (IOException ex) {
            ex.printStackTrace();
            return;
        }
    }
}
