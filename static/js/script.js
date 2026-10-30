// script.js - small, simple JavaScript for Privacy Monitor.
// Each block only runs if the matching element exists on the current page.

document.addEventListener("DOMContentLoaded", function () {

    // ---------- Helper: show a small message box ----------
    function showMessage(id, text) {
        var box = document.getElementById(id);
        if (box) {
            box.textContent = text;
            box.style.display = "block";
        }
    }

    // ---------- Simple demo buttons (data-message="..." data-target="boxId") ----------
    document.querySelectorAll("[data-message]").forEach(function (btn) {
        btn.addEventListener("click", function () {
            showMessage(btn.dataset.target, btn.dataset.message);
        });
    });

    // ---------- Basic form validation (forms with class "validate") ----------
    document.querySelectorAll("form.validate").forEach(function (form) {
        form.addEventListener("submit", function (event) {
            event.preventDefault();          // no backend yet, so we stop the real submit
            var ok = true;

            // Every field marked "required" must be filled in
            form.querySelectorAll("[required]").forEach(function (field) {
                var err = field.parentElement.querySelector(".error");
                if (err) err.textContent = "";
                if (field.value.trim() === "") {
                    if (err) err.textContent = "This field is required.";
                    ok = false;
                } else if (field.type === "email" && field.value.indexOf("@") === -1) {
                    if (err) err.textContent = "Please enter a valid email address.";
                    ok = false;
                } else if (field.type === "password" && field.value.length < 8 && field.dataset.minlength) {
                    if (err) err.textContent = "Password must be at least 8 characters.";
                    ok = false;
                }
            });

            // Registration: the two passwords must match
            var p1 = form.querySelector("#password");
            var p2 = form.querySelector("#confirm_password");
            if (p1 && p2 && p2.value !== "" && p1.value !== p2.value) {
                p2.parentElement.querySelector(".error").textContent = "Passwords do not match.";
                ok = false;
            }

            if (ok) {
                var msg = form.dataset.success || "Form is valid (demo only, nothing was saved).";
                showMessage(form.dataset.messageBox || "form-message", msg);
                // Optional: go to another page after a valid demo submit
                // (short delay so the message can be read first)
                if (form.dataset.redirect) {
                    setTimeout(function () {
                        window.location.href = form.dataset.redirect;
                    }, 1200);
                }
            }
        });
    });

    // ---------- Reference photo preview (Monitoring page) ----------
    var photoInput = document.getElementById("photo");
    var preview = document.getElementById("photo-preview");
    var removePhoto = document.getElementById("remove-photo");
    if (photoInput && preview) {
        photoInput.addEventListener("change", function () {
            var file = photoInput.files[0];
            if (file && file.type.indexOf("image/") === 0) {
                preview.src = URL.createObjectURL(file);   // show the chosen image
                preview.style.display = "block";
            }
        });
        removePhoto.addEventListener("click", function () {
            photoInput.value = "";
            preview.src = "";
            preview.style.display = "none";
        });
    }

    // ---------- Monitoring on/off toggle (text only changes) ----------
    document.querySelectorAll(".monitor-toggle").forEach(function (box) {
        box.addEventListener("change", function () {
            var status = document.getElementById(box.dataset.status);
            if (status) status.textContent = box.checked ? "Monitoring is ON (demo)" : "Monitoring is OFF (demo)";
        });
    });

    // ---------- Scan results filters ----------
    var catFilter = document.getElementById("filter-category");
    var riskFilter = document.getElementById("filter-risk");
    if (catFilter && riskFilter) {
        function applyFilters() {
            document.querySelectorAll("#findings-table tbody tr.finding-row").forEach(function (row) {
                var okCat = catFilter.value === "all" || row.dataset.category === catFilter.value;
                var okRisk = riskFilter.value === "all" || row.dataset.risk === riskFilter.value;
                row.style.display = (okCat && okRisk) ? "" : "none";
            });
        }
        catFilter.addEventListener("change", applyFilters);
        riskFilter.addEventListener("change", applyFilters);
    }

    // ---------- Show/hide details (View Details buttons) ----------
    document.querySelectorAll("[data-toggle]").forEach(function (btn) {
        btn.addEventListener("click", function () {
            var target = document.getElementById(btn.dataset.toggle);
            if (target) target.classList.toggle("hidden");
        });
    });

    // ---------- Questionnaire (one question at a time) ----------
    var questions = document.querySelectorAll(".question");
    if (questions.length > 0) {
        var current = 0;
        var prevBtn = document.getElementById("prev-btn");
        var nextBtn = document.getElementById("next-btn");
        var submitBtn = document.getElementById("submit-btn");
        var progressText = document.getElementById("progress-text");
        var progressFill = document.getElementById("progress-fill");
        var qError = document.getElementById("question-error");

        function showQuestion() {
            questions.forEach(function (q, i) {
                q.classList.toggle("active", i === current);
            });
            prevBtn.style.visibility = current === 0 ? "hidden" : "visible";
            nextBtn.style.display = current === questions.length - 1 ? "none" : "inline-block";
            submitBtn.style.display = current === questions.length - 1 ? "inline-block" : "none";
            progressText.textContent = "Question " + (current + 1) + " of " + questions.length;
            progressFill.style.width = ((current + 1) / questions.length * 100) + "%";
            qError.textContent = "";
        }

        function answered() {
            return questions[current].querySelector("input:checked") !== null;
        }

        nextBtn.addEventListener("click", function () {
            if (!answered()) { qError.textContent = "Please choose an answer first."; return; }
            current++;
            showQuestion();
        });
        prevBtn.addEventListener("click", function () {
            current--;
            showQuestion();
        });

        submitBtn.addEventListener("click", function () {
            if (!answered()) { qError.textContent = "Please choose an answer first."; return; }

            // Each radio value is 0 (safest), 1 or 2 (riskiest). Add them up.
            var total = 0;
            document.querySelectorAll(".question input:checked").forEach(function (r) {
                total += parseInt(r.value);
            });
            var max = questions.length * 2;
            var score = Math.round(total / max * 100);   // 0 = low exposure, 100 = high

            var category, explanation;
            if (score < 34) {
                category = "Low";
                explanation = "Your answers suggest good privacy habits.";
            } else if (score < 67) {
                category = "Medium";
                explanation = "Some of your answers suggest information may be easy to find.";
            } else {
                category = "High";
                explanation = "Your answers suggest a lot of your information may be exposed.";
            }

            document.getElementById("result-score").textContent = score + " / 100";
            document.getElementById("result-category").textContent = category;
            document.getElementById("result-explanation").textContent = explanation;
            document.getElementById("quiz-section").classList.add("hidden");
            document.getElementById("result-section").classList.remove("hidden");
        });

        showQuestion();
    }

    // ---------- Questionnaire: take it again ----------
    var retake = document.getElementById("retake-btn");
    if (retake) {
        retake.addEventListener("click", function () { window.location.reload(); });
    }

    // ---------- Evidence file name (Cases page) ----------
    var evInput = document.getElementById("evidence");
    var evName = document.getElementById("evidence-name");
    var evRemove = document.getElementById("remove-evidence");
    if (evInput && evName) {
        evInput.addEventListener("change", function () {
            evName.textContent = evInput.files[0] ? "Selected file: " + evInput.files[0].name : "No file selected.";
        });
        evRemove.addEventListener("click", function () {
            evInput.value = "";
            evName.textContent = "No file selected.";
        });
    }
});
