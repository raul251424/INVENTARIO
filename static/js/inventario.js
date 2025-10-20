document.addEventListener('DOMContentLoaded', function () {

    // --- LÓGICA DE BORRADO ÚNICO ---
    const confirmDeleteModal = document.getElementById('confirmDeleteModal');
    if (confirmDeleteModal) {
        const deleteForm = document.getElementById('deleteForm');
        confirmDeleteModal.addEventListener('show.bs.modal', function (event) {
            const button = event.relatedTarget;
            const productId = button.getAttribute('data-product-id');
            const productName = button.getAttribute('data-product-name');
            const modalProductName = confirmDeleteModal.querySelector('#productName');
            
            modalProductName.textContent = productName;
            // Aseguramos que la URL base se construye correctamente
            const baseUrl = window.location.origin;
            deleteForm.action = `${baseUrl}/panel/producto/borrar/${productId}`;
        });

        deleteForm.addEventListener('submit', function (event) {
            event.preventDefault();
            const form = event.target;
            
            fetch(form.action, {
                method: 'POST',
                body: new FormData(form),
                headers: {
                    'X-CSRF-Token': form.querySelector('input[name="csrf_token"]').value
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    window.location.reload();
                } else {
                    alert('Error al eliminar el producto: ' + (data.message || 'Error desconocido.'));
                    const modal = bootstrap.Modal.getInstance(confirmDeleteModal);
                    if (modal) modal.hide();
                }
            })
            .catch(error => {
                console.error('Error en la petición de borrado:', error);
                alert('Ocurrió un error de red. Inténtalo de nuevo.');
            });
        });
    }

    // --- LÓGICA DE SELECCIÓN MASIVA ---
    const selectAllCheckbox = document.getElementById('selectAllProducts');
    const productCheckboxes = document.querySelectorAll('.product-checkbox');
    const borrarSeleccionadosBtn = document.getElementById('borrarSeleccionadosBtn');
    const countSelectedSpan = document.getElementById('countSelected');

    function updateSelectedCount() {
        const checkedCount = document.querySelectorAll('.product-checkbox:checked').length;
        if (countSelectedSpan) {
            countSelectedSpan.textContent = checkedCount;
        }
        if (borrarSeleccionadosBtn) {
            borrarSeleccionadosBtn.disabled = (checkedCount === 0);
        }
        // Sincronizar el checkbox "seleccionar todo"
        if (selectAllCheckbox) {
            selectAllCheckbox.checked = (productCheckboxes.length > 0 && checkedCount === productCheckboxes.length);
        }
    }

    if (selectAllCheckbox) {
        selectAllCheckbox.addEventListener('change', function () {
            productCheckboxes.forEach(checkbox => {
                checkbox.checked = this.checked;
            });
            updateSelectedCount();
        });
    }

    productCheckboxes.forEach(checkbox => {
        checkbox.addEventListener('change', updateSelectedCount);
    });

    // Llamada inicial para establecer el estado correcto al cargar la página
    updateSelectedCount();

    // --- LÓGICA DE BORRADO MASIVO CON MODAL (CORREGIDA) ---
    const massDeleteModalEl = document.getElementById('confirmMassDeleteModal');
    const massDeleteForm = document.getElementById('massDeleteForm');

    if (massDeleteModalEl && massDeleteForm) {
        const massModalText = document.getElementById('massModalText');
        const confirmMassDeleteBtn = document.getElementById('confirmMassDeleteBtn');
        const urlSeleccion = massDeleteForm.getAttribute('data-url-seleccion');
        const urlTodo = massDeleteForm.getAttribute('data-url-todo');

        massDeleteModalEl.addEventListener('show.bs.modal', function (event) {
            const button = event.relatedTarget;
            const mode = button.getAttribute('data-mode');
            
            // Guardar el modo en el botón de confirmación del modal
            confirmMassDeleteBtn.setAttribute('data-mode', mode);
            
            if (mode === 'selected') {
                const count = document.querySelectorAll('.product-checkbox:checked').length;
                massModalText.innerHTML = `¿Estás seguro de que deseas eliminar permanentemente <strong>${count} productos seleccionados</strong>?`;
            } else if (mode === 'all') {
                massModalText.innerHTML = `<strong>¡ADVERTENCIA!</strong> Esta acción eliminará todo el inventario de forma permanente. ¿Deseas continuar?`;
            }
        });

        confirmMassDeleteBtn.addEventListener('click', function () {
            const mode = this.getAttribute('data-mode');

            if (mode === 'selected') {
                massDeleteForm.action = urlSeleccion;
            } else if (mode === 'all') {
                massDeleteForm.action = urlTodo;
            }

            // ¡IMPORTANTE! Simplemente enviamos el formulario.
            // No deshabilitamos ningún checkbox. El navegador solo enviará los que están marcados.
            if (massDeleteForm.action) {
                massDeleteForm.submit();
            }
        });
    }
});