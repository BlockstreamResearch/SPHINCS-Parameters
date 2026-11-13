# Single entrypoint for regenerating every derived artifact.
#
#   make generate   — everything below, in dependency order
#   make sweeps     — the two parameter sweeps -> analysis/*.csv     (sage)
#   make derived    — thresholds + extremes from the sweep CSVs      (python)
#   make data       — site/data.json for both site pages             (sage)
#   make figures    — report figures from the generated data         (python)
#   make test       — regression suite (validates artifacts <-> model)
#   make check-local — pre-push validation w/o sage
#   make fixtures   — golden values in tests/fixtures.json that differ from the code (WRITE=1 updates them)
#   make site-snapshot — numbers on the site pages vs tests/site_snapshot.json (UPDATE=1 records them)
#   make clean-generated

SAGE   ?= sage
PYTHON ?= python3

ANALYSIS := analysis
IMAGES   := document/content/images

CSV_CAPPED  := $(ANALYSIS)/all_size_capped_candidates.csv
CSV_UNBOUND := $(ANALYSIS)/all_unbound_candidates.csv

.PHONY: generate sweeps derived data figures test check-local fixtures site-snapshot clean-generated

generate: sweeps derived data figures test

sweeps:
	$(SAGE) scripts/slhdsa-2to40.sage > /dev/null
	mv candidates.csv $(CSV_CAPPED)
	$(SAGE) scripts/slhdsa-2to40.sage --max-size 99999999 > /dev/null
	mv candidates.csv $(CSV_UNBOUND)

derived:
	cd $(ANALYSIS) && $(PYTHON) min_mult_search.py
	$(PYTHON) $(ANALYSIS)/extremes_summary.py

data:
	$(SAGE) scripts/export_site_data.sage

figures:
	mkdir -p $(IMAGES)   # holds only generated files, so fresh checkouts lack it
	cd $(IMAGES) && $(PYTHON) ../../../$(ANALYSIS)/sieve_search_draw.py \
	    --input ../../../$(CSV_UNBOUND) --weights 1,1,1,1,1 --suffix _1
	cd $(IMAGES) && $(PYTHON) ../../../$(ANALYSIS)/sieve_search_draw.py \
	    --input ../../../$(CSV_UNBOUND) --weights 5,1,1.5,2,1 --suffix _2
	cd $(ANALYSIS) && $(PYTHON) venn_diagram_draw.py
	mv $(ANALYSIS)/euler_custom_minimax.png $(IMAGES)/concentric_diagram.png
	cd $(IMAGES) && $(PYTHON) ../../../$(ANALYSIS)/plot_concept_scatter.py
	mv $(IMAGES)/conceptual_bounded_zones_origin_vector.png $(IMAGES)/scatter_plot.png
	# Report Sec. "Metric-Normalized Weighted Distance": method comparison
	cd $(IMAGES) && $(PYTHON) ../../../$(ANALYSIS)/sieve_search_draw.py \
	    --input ../../../$(CSV_UNBOUND) --figure focus --distance regular \
	    --x-size 0.75 --x-kg 5 --x-sg 5 --x-sv 1.5 --x-cb 1 \
	    --weights 5,1.5,1.5,2,1 --out comparison_regular.png
	cd $(IMAGES) && $(PYTHON) ../../../$(ANALYSIS)/sieve_search_draw.py \
	    --input ../../../$(CSV_UNBOUND) --figure focus --distance normalized \
	    --x-size 0.75 --x-kg 5 --x-sg 5 --x-sv 1.5 --x-cb 1 \
	    --weights 5,1.5,1.5,2,1 --out comparison_normalized.png
	# Report Sec. "Recommended Candidate Tuple": the two surviving candidates
	cd $(IMAGES) && $(PYTHON) ../../../$(ANALYSIS)/sieve_search_draw.py \
	    --input ../../../$(CSV_UNBOUND) --figure focus --distance regular --annotate \
	    --x-size 0.74 --x-kg 2 --x-sg 2 --x-sv 0.8 --x-cb 1 \
	    --weights 5,1,1,2,1 --out ideal_candidate_balanced.png
	cd $(IMAGES) && $(PYTHON) ../../../$(ANALYSIS)/sieve_search_draw.py \
	    --input ../../../$(CSV_UNBOUND) --figure focus --distance normalized --annotate \
	    --x-size 0.74 --x-kg 2 --x-sg 2 --x-sv 0.8 --x-cb 1 \
	    --weights 5,1,1,2,1 --out ideal_candidate_best.png

test:
	$(PYTHON) tests/run.py

check-local:
	$(PYTHON) tests/synth_generated.py
	GENERATED_REQUIRED=1 $(PYTHON) tests/run.py

fixtures:
	$(PYTHON) tests/regen_fixtures.py $(if $(WRITE),--write)

# Needs site/data.json and, once: npm install && npx playwright install chromium
site-snapshot:
	node tests/site_snapshot.js $(if $(UPDATE),--update)

clean-generated:
	rm -f $(CSV_CAPPED) $(CSV_UNBOUND)
	rm -f $(ANALYSIS)/global_X_thresholds.csv $(ANALYSIS)/master_extremes_summary.csv
	rm -f site/data.json site/report.pdf
	rm -f $(IMAGES)/sieve_step*.png $(IMAGES)/concentric_diagram.png $(IMAGES)/scatter_plot.png
	rm -f $(IMAGES)/comparison_regular.png $(IMAGES)/comparison_normalized.png
	rm -f $(IMAGES)/ideal_candidate_balanced.png $(IMAGES)/ideal_candidate_best.png
