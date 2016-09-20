CAPTURE_FILES=data/wired_lan data/shopping data/starbucks
CAPTURE_PDF=$(addsuffix .pdf, $(CAPTURE_FILES))

.PHONY: all clean

all: $(CAPTURE_PDF)

clean:
	rm -rf $(CAPTURE_PDF) data/*.csv

$(CAPTURE_PDF):
	./src/sniffer.py -f $(subst pdf,pcap,$@) --output-graph $(subst .pdf,,$@)
	java -jar extra/gephi_network_renderer.jar $(subst .pdf,,$@)
