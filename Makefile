CAPTURE_FILES=data/wired_lan data/shopping data/starbucks
CAPTURE_PDF=$(addsuffix .pdf, $(CAPTURE_FILES))
EXP_DIR=exp/
FIGURES_DIR=latex/figures/
GEPHI_RENDERER_JAR=tools/gephi_network_renderer/out/artifacts/gephi_network_renderer_jar/gephi_network_renderer.jar

.PHONY: all clean

all: $(CAPTURE_PDF)

clean:
	rm -rf $(CAPTURE_PDF) exp/*

$(CAPTURE_PDF):
	./src/sniffer.py -f $(subst pdf,pcap.gz,$@) -o \
		$(addprefix $(EXP_DIR), $(notdir $(subst .pdf,,$@)))
	java -jar $(GEPHI_RENDERER_JAR) \
		$(addprefix $(EXP_DIR), $(notdir $(subst .pdf,,$@))) $(FIGURES_DIR)
