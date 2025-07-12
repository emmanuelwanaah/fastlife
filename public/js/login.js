// // Show price / bed type if you add those in your DB later.

// // Add reservation expiration countdown on dashboard.

// // Add success modal instead of just alert() on success.

// // Store selection in sessionStorage so refreshing doesn't reset it entirely.


// <!DOCTYPE html>
// <html lang="en">
// <head>
//   <meta charset="UTF-8" />
//   <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
//   <title>Room Booking</title>
//   <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"/>
//   <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
//   <!--=============== REMIXICONS ===============-->
//   <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/remixicon/4.2.0/remixicon.css">
  
// </head>
// <body>

// <div class="container mt-5">
    
      
//   <div class="row shadow" style="border-radius: 10px; overflow: hidden;">
//     <!-- Sidebar -->
//     <div class="col-md-4 step-sidebar">
//         <div class="alert alert-info" id="userGenderBadge" style="display:none;">
//             <strong>Booking for:</strong> <span id="genderText"></span> student
//           </div>
//       <div class="step-item active" id="step-label-1">1. Select Hall</div>
//       <div class="step-item" id="step-label-2">2. Select Room</div>
//       <div class="step-item" id="step-label-3">3. Select Bed</div>
//       <div class="step-item" id="step-label-4">4. Confirm</div>
//     </div>

//     <!-- Form Content -->
//     <div class="col-md-8 step-content">

//       <!-- Step 1 -->
//       <div class="form-step active" id="step1">
//         <h4>Select Hall</h4>
//         <select id="hallSelect" class="form-select mb-3">
//           <option value="">-- Choose a Hall --</option>
//         </select>
//         <div class="step-actions">
//           <button class="btn btn-primary" onclick="goToStep(2)">Next</button>
//         </div>
//       </div>

//       <!-- Step 2 -->
//       <div class="form-step" id="step2">
//         <h4>Select Room</h4>
//         <select id="roomSelect" class="form-select mb-3"></select>
//         <div class="step-actions">
//           <button class="btn btn-secondary" onclick="goToStep(1)">Back</button>
//           <button class="btn btn-primary" onclick="goToStep(3)">Next</button>
//         </div>
//       </div>

//       <!-- Step 3 -->
//       <div class="form-step" id="step3">
//         <h4>Select Bed</h4>
//         <select id="bedSelect" class="form-select mb-3"></select>
//         <div class="step-actions">
//           <button class="btn btn-secondary" onclick="goToStep(2)">Back</button>
//           <button class="btn btn-primary" onclick="goToStep(4)">Next</button>
//         </div>
//       </div>

//       <!-- Step 4 -->
//       <div class="form-step" id="step4">
//         <h4>Confirm Booking</h4>
//         <p><strong>Hall:</strong> <span id="confirmHall"></span></p>
//         <p><strong>Room:</strong> <span id="confirmRoom"></span></p>
//         <p><strong>Bed:</strong> <span id="confirmBed"></span></p>
//         <div class="step-actions">
//           <button class="btn btn-secondary" onclick="goToStep(3)">Back</button>
//           <button class="btn btn-success" onclick="submitBooking()">Book Now</button>
//         </div>
//       </div>

//     </div>
//   </div>
// </div>

// <script>






//     window.addEventListener('DOMContentLoaded', () => {

  
//         // Load user gender for badge
//         fetch('/api/user-info')
//           .then(res => res.json())
//           .then(user => {
//             document.getElementById('genderText').textContent = user.gender;
//             document.getElementById('userGenderBadge').style.display = 'block';
//           });
      
//         // Load rooms filtered by gender (already handled by backend)
//         fetch('/api/available-rooms')
//           .then(res => res.json())
//           .then(data => {
//             hallData = data;
//             const halls = [...new Set(data.map(item => item.hall_name))];
//             const hallSelect = document.getElementById('hallSelect');
//             halls.forEach(hall => {
//               hallSelect.innerHTML += `<option value="${hall}">${hall}</option>`;
//             });
//           });
//       });
      









//     <!-- gender finish----------------------- -->
//   let step = 1;
//   let hallData = [];
//   let selectedHall = "", selectedRoom = "", selectedBed = "";

//   function updateSidebar() {
//     for (let i = 1; i <= 4; i++) {
//       const label = document.getElementById(`step-label-${i}`);
//       label.classList.remove("active", "done");
//       if (i < step) label.classList.add("done");
//       else if (i === step) label.classList.add("active");
//     }
//   }

//   function goToStep(s) {
//     step = s;
//     document.querySelectorAll(".form-step").forEach(f => f.classList.remove("active"));
//     document.getElementById(`step${s}`).classList.add("active");
//     updateSidebar();

//     if (s === 2) loadRooms();
//     if (s === 3) loadBeds();
//     if (s === 4) showConfirmation();
//   }

//   window.addEventListener('DOMContentLoaded', () => {
//     fetch('/api/available-rooms')
//       .then(res => res.json())
//       .then(data => {
//         hallData = data;
//         const halls = [...new Set(data.map(item => item.hall_name))];
//         const hallSelect = document.getElementById('hallSelect');
//         halls.forEach(hall => {
//           hallSelect.innerHTML += `<option value="${hall}">${hall}</option>`;
//         });
//       });
//   });

//   function loadRooms() {
//     selectedHall = document.getElementById("hallSelect").value;
//     const roomSelect = document.getElementById("roomSelect");
//     roomSelect.innerHTML = `<option value="">-- Select Room --</option>`;
//     const rooms = [...new Set(hallData.filter(r => r.hall_name === selectedHall).map(r => r.room_number))];
//     rooms.forEach(room => {
//       roomSelect.innerHTML += `<option value="${room}">${room}</option>`;
//     });
//   }

//   function loadBeds() {
//     selectedRoom = document.getElementById("roomSelect").value;
//     const bedSelect = document.getElementById("bedSelect");
//     bedSelect.innerHTML = `<option value="">-- Select Bed --</option>`;
//     const beds = hallData.filter(
//       b => b.hall_name === selectedHall && b.room_number === selectedRoom && !b.reservation_id
//     );
//     beds.forEach(bed => {
//       bedSelect.innerHTML += `<option value="${bed.bed_id}">Bed ${bed.bed_number}</option>`;
//     });
//   }

//   function showConfirmation() {
//     selectedBed = document.getElementById("bedSelect").value;
//     const bed = hallData.find(b => b.bed_id == selectedBed);
//     document.getElementById("confirmHall").textContent = bed.hall_name;
//     document.getElementById("confirmRoom").textContent = bed.room_number;
//     document.getElementById("confirmBed").textContent = `Bed ${bed.bed_number}`;
//   }

//   function submitBooking() {
//     fetch('/api/book-bed', {
//       method: 'POST',
//       headers: { 'Content-Type': 'application/json' },
//       body: JSON.stringify({ bedId: selectedBed })
//     })
//       .then(res => res.json())
//       .then(data => {
//         if (data.success) {
//           alert("Booking successful!");
//           location.reload();
//         } else {
//           alert(data.message || "Booking failed.");
//         }
//       });
//   }

// </script>

// </body>
// </html>
