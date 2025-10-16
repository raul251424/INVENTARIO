document.addEventListener('DOMContentLoaded', function () {
    console.log("¡El archivo externo de JavaScript se ha cargado correctamente!");

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
            deleteForm.action = '/panel/producto/borrar/' + productId;
        });

        deleteForm.addEventListener('submit', function (event) {
            event.preventDefault();
            const form = event.target;
            const url = form.action;
            const formData = new FormData(form);

            fetch(url, {
                method: 'POST',
                body: formData,
                headers: { 'X-CSRFToken': formData.get('csrf_token') }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    window.location.reload();
                } else {
                    const modal = bootstrap.Modal.getInstance(confirmDeleteModal);
                    modal.hide();
                    alert('Error al eliminar el producto: ' + data.message);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Ocurrió un error de red. Inténtalo de nuevo.');
            });
        });
    }

    // --- LÓGICA DE SELECCIÓN MASIVA ---
    const selectAllCheckbox = document.getElementById('selectAllProducts');
    const productCheckboxes = document.querySelectorAll('.product-checkbox');
    const borrarSeleccionadosBtn = document.getElementById('borrarSeleccionadosBtn');
    const countSelected = document.getElementById('countSelected');

    function updateSelectedCount() {
        const checkedCount = document.querySelectorAll('.product-checkbox:checked').length;
        if (countSelected) countSelected.textContent = checkedCount;
        if (borrarSeleccionadosBtn) borrarSeleccionadosBtn.disabled = checkedCount === 0;
    }

    if (selectAllCheckbox) {
        selectAllCheckbox.addEventListener('change', function () {
            productCheckboxes.forEach(checkbox => {
                checkbox.checked = selectAllCheckbox.checked;
            });
            updateSelectedCount();
        });
    }

    productCheckboxes.forEach(checkbox => {
        checkbox.addEventListener('change', function () {
            updateSelectedCount();
            if (selectAllCheckbox && document.querySelectorAll('.product-checkbox:checked').length !== productCheckboxes.length) {
                selectAllCheckbox.checked = false;
            }
        });
    });

    updateSelectedCount();

    // --- LÓGICA DE BORRADO MASIVO CON MODAL ---
    const confirmMassDeleteModal = document.getElementById('confirmMassDeleteModal');
    const massDeleteForm = document.getElementById('massDeleteForm');

    if (confirmMassDeleteModal && massDeleteForm) {
        const massModalText = document.getElementById('massModalText');
        const confirmMassDeleteBtn = document.getElementById('confirmMassDeleteBtn');
        
        // Obtenemos las URLs desde los atributos data-* en el formulario
        const urlSeleccion = massDeleteForm.getAttribute('data-url-seleccion');
        const urlTodo = massDeleteForm.getAttribute('data-url-todo');

        confirmMassDeleteModal.addEventListener('show.bs.modal', function (event) {
            const button = event.relatedTarget;
            const mode = button.getAttribute('data-mode');
            
            confirmMassDeleteBtn.setAttribute('data-mode', mode);
            
            if (mode === 'selected') {
                const count = document.querySelectorAll('.product-checkbox:checked').length;
                massModalText.innerHTML = `¿Estás seguro de que deseas eliminar permanentemente **${count} productos seleccionados**?`;
            } else if (mode === 'all') {
                massModalText.innerHTML = `**ESTA ACCIÓN ELIMINARÁ TODO EL INVENTARIO.** ¿Deseas continuar?`;
            }
        });

        confirmMassDeleteBtn.addEventListener('click', function () {
            const mode = this.getAttribute('data-mode');

            if (mode === 'selected') {
                massDeleteForm.action = urlSeleccion;
                productCheckboxes.forEach(checkbox => {
                    if (!checkbox.checked) {
                        checkbox.disabled = true;
                    }
                });
            } else if (mode === 'all') {
                massDeleteForm.action = urlTodo;
            }

            if (massDeleteForm.action) {
                massDeleteForm.submit();
            }
        });
    }
});