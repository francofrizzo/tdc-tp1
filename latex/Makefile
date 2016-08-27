.PHONY: all clean clean_aux

TEX=informe.tex sections/1-introduccion.tex
PDF=informe

# LaTeX flags
TEXFLAGS=-file-line-error -interaction=nonstopmode

all: $(PDF)

$(PDF): $(TEX)
	@ [ ! -f $(@:pdf=aux) ] || md5sum $(@:pdf=aux) > .auxmd5
	# [ ! -f $(@:pdf=aux) ] || bibtex $(@:pdf=aux)
	@ pdflatex $(TEXFLAGS) -jobname $(PDF) $<
	@ if [ "x$(shell cat .auxmd5)" '!=' "x$(shell md5sum $(@:pdf=aux))" ]; then echo "Relatexing..." 1>&2; rm $@; make $@; fi

clean: clean_aux
	rm $(PDF).pdf

clean_aux:
	rm -f *.aux *.log *.out *.toc *.nav *.snm
