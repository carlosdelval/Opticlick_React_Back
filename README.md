
---

### **Backend README.md** (Node.js)  

```markdown
# OptiClick Backend - Eye Care API ⚙️  

![Node.js](https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=nodedotjs&logoColor=white)
![Express](https://img.shields.io/badge/Express-000000?style=for-the-badge&logo=express&logoColor=white)
![MongoDB](https://img.shields.io/badge/MongoDB-47A248?style=for-the-badge&logo=mongodb&logoColor=white)  

> **Final Degree Project Backend** - REST API powering OptiClick's appointment scheduling and patient history features.  

## 🔧 Key Functionality  
- **Authentication** (JWT) for patients/opticians  
- **CRUD Operations** for:  
  - 👥 User profiles  
  - 🗓️ Appointments  
  - 👁️ Vision history records  
- **Data validation** with Joi  

## � Endpoints  
| Method | Route                | Description              |  
|--------|----------------------|--------------------------|  
| POST   | `/api/auth/register` | Patient registration     |  
| GET    | `/api/appointments`  | Fetch booked sessions    |  

## 🚀 Deployment  
```bash
git clone https://github.com/carlosdelval/Opticlick_Backend.git
npm install
npm run dev  # Development
npm start    # Production
